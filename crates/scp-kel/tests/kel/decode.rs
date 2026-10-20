//! `decode_preimage`'s rejections (`09-security-model.md` §9.7.4.2): the
//! count-bound rule, truncation at every fixed field, trailing bytes,
//! unregistered discriminators, and the `compromised_from` rule. Each test
//! mutates one byte or one length of a spec 25 vector's field bytes.

use scp_did::{
    CommitmentEntry, CustodyType, DiscriminatorKind, Identifier, KeyAlgorithm, KeyCondition,
    UnknownDiscriminator,
};
use scp_kel::constants::{
    MAX_EVENT_BYTES, MAX_NEXT_SET_SIZE, MAX_ROOT_SET_SIZE, MAX_WITNESS_SET_SIZE,
};
use scp_kel::{
    CommitmentRolloverFields, Continuation, DecodeError, DiscriminatorField, EncodeError,
    EventDiscriminatorField, EventKind, EventPreimage, ListField, PreimageField, SignatureForm,
    SignerGroup, decode_preimage, encode_preimage,
};

use crate::fixtures::{
    TestResult, V41_DIGEST, V41_IDENTIFIER, V41_PREIMAGE, V50_PREIMAGE, array, fields, identifier,
    v41_inception,
};

// Offsets into Vector 41's 347 field bytes (its 364 printed bytes after the
// 17-byte separator), from §9.7.4.2's field order. `vector_41_offsets_land_on_their_fields`
// checks each against the byte it must hold.
const KIND: usize = 0;
const STANDING_ROOT: usize = 73;
const INDEX_COUNT: usize = 74;
const FORM_COUNT: usize = 79;
const FORM: usize = 83;
const REVEALED_COUNT: usize = 84;
const ROOT_SET_COUNT: usize = 88;
const KEY_COUNT: usize = 133;
const ENTRY_0: usize = 137;
const ENTRY_1: usize = ENTRY_0 + 45;
/// Within a key entry: role, condition, `compromised_from`, custody, algorithm.
const ROLE: usize = 33;
const CONDITION: usize = 34;
const COMPROMISED_FROM: usize = 35;
const CUSTODY: usize = 43;
const ALGORITHM: usize = 44;
const WITNESS_COUNT: usize = 227;
const SERVICE_KEY_ROLE: usize = 267;
const SEAL_COUNT: usize = 300;
const CONTINUATION: usize = 304;
const COMMITMENT_COUNT: usize = 305;
const COMMITMENT_CUSTODY: usize = 341;
const COMMITMENT_ALGORITHM: usize = 342;
const V41_FIELD_LEN: usize = 347;
/// Vector 50's seal count, after its 4-byte field 9 sentinel and its
/// 171-byte snapshot.
const V50_SEAL_COUNT: usize = 263;

fn v41_fields() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    fields(V41_PREIMAGE)
}

fn v41_with(offset: usize, value: u8) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = v41_fields()?;
    *bytes.get_mut(offset).ok_or("offset past Vector 41")? = value;
    Ok(bytes)
}

fn count_at(bytes: &[u8], offset: usize) -> Result<u32, Box<dyn std::error::Error>> {
    let window = bytes.get(offset..offset + 4).ok_or("count past the end")?;
    Ok(u32::from_be_bytes(<[u8; 4]>::try_from(window)?))
}

#[test]
fn vector_41_offsets_land_on_their_fields() -> TestResult {
    let bytes = v41_fields()?;
    assert_eq!(bytes.len(), V41_FIELD_LEN);
    assert_eq!(bytes.get(KIND), Some(&0x01));
    assert_eq!(bytes.get(STANDING_ROOT), Some(&0x00));
    assert_eq!(count_at(&bytes, INDEX_COUNT)?, 1);
    assert_eq!(count_at(&bytes, FORM_COUNT)?, 1);
    assert_eq!(bytes.get(FORM), Some(&0x01));
    assert_eq!(count_at(&bytes, REVEALED_COUNT)?, 0);
    assert_eq!(count_at(&bytes, ROOT_SET_COUNT)?, 1);
    assert_eq!(count_at(&bytes, KEY_COUNT)?, 2);
    assert_eq!(bytes.get(ENTRY_0 + ROLE), Some(&0x01));
    assert_eq!(bytes.get(ENTRY_1 + ROLE), Some(&0x02));
    assert_eq!(bytes.get(ENTRY_0 + CONDITION), Some(&0x01));
    assert_eq!(
        bytes.get(ENTRY_0 + COMPROMISED_FROM..ENTRY_0 + CUSTODY),
        Some(&[0u8; 8][..])
    );
    assert_eq!(bytes.get(ENTRY_0 + CUSTODY), Some(&0x01));
    assert_eq!(bytes.get(ENTRY_0 + ALGORITHM), Some(&0x01));
    assert_eq!(count_at(&bytes, WITNESS_COUNT)?, 1);
    assert_eq!(bytes.get(SERVICE_KEY_ROLE), Some(&0x02));
    assert_eq!(count_at(&bytes, SEAL_COUNT)?, 0);
    assert_eq!(bytes.get(CONTINUATION), Some(&0x01));
    assert_eq!(count_at(&bytes, COMMITMENT_COUNT)?, 1);
    assert_eq!(bytes.get(COMMITMENT_CUSTODY), Some(&0x01));
    assert_eq!(bytes.get(COMMITMENT_ALGORITHM), Some(&0x01));
    assert_eq!(count_at(&fields(V50_PREIMAGE)?, V50_SEAL_COUNT)?, 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// The count-bound rule: each list over its §9.18.17 maximum by one, and each
// at its maximum, which decodes.
// ---------------------------------------------------------------------------

fn assert_over_max(preimage: &EventPreimage, list: ListField, max: u32) -> TestResult {
    assert_eq!(
        decode_preimage(&encode_preimage(preimage)?),
        Err(DecodeError::CountOverMax {
            list,
            count: max + 1,
            max
        })
    );
    Ok(())
}

fn assert_decodes(preimage: &EventPreimage) -> TestResult {
    assert_eq!(&decode_preimage(&encode_preimage(preimage)?)?, preimage);
    Ok(())
}

fn n(count: u32) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(usize::try_from(count)?)
}

fn with_indices(count: u32) -> Result<EventPreimage, Box<dyn std::error::Error>> {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    let group = preimage.signer_groups.first_mut().ok_or("no group")?;
    group.indices = vec![0; n(count)?];
    Ok(preimage)
}

fn with_forms(count: u32) -> Result<EventPreimage, Box<dyn std::error::Error>> {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    let group = preimage.signer_groups.first_mut().ok_or("no group")?;
    group.forms = vec![SignatureForm::Raw; n(count)?];
    Ok(preimage)
}

fn with_revealed_keys(count: u32) -> Result<EventPreimage, Box<dyn std::error::Error>> {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    preimage.revealed_keys = vec![[2; 33]; n(count)?];
    Ok(preimage)
}

fn with_root_members(count: u32) -> Result<EventPreimage, Box<dyn std::error::Error>> {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    let root_set = preimage.installed_root_set.as_mut().ok_or("no root set")?;
    root_set.members = vec![[3; 33]; n(count)?];
    Ok(preimage)
}

fn with_witnesses(count: u32) -> Result<EventPreimage, Box<dyn std::error::Error>> {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    let snapshot = preimage.key_state.as_mut().ok_or("no snapshot")?;
    snapshot.witnesses = vec![Identifier::from_bytes([9; 32]); n(count)?];
    Ok(preimage)
}

fn with_commitments(count: u32) -> Result<EventPreimage, Box<dyn std::error::Error>> {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    let Some(Continuation::FixesCommitment(commitment)) = preimage.continuation.as_mut() else {
        return Err("Vector 41 fixes a commitment".into());
    };
    commitment.commitments = vec![
        CommitmentEntry {
            commitment: [4; 32],
            custody_type: CustodyType::Software,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        };
        n(count)?
    ];
    Ok(preimage)
}

#[test]
fn signer_index_list_over_its_maximum_is_rejected() -> TestResult {
    let max = MAX_ROOT_SET_SIZE.max(MAX_NEXT_SET_SIZE);
    assert_over_max(&with_indices(max + 1)?, ListField::SignerIndices, max)?;
    assert_decodes(&with_indices(max)?)
}

#[test]
fn signature_form_list_over_its_maximum_is_rejected() -> TestResult {
    let max = MAX_ROOT_SET_SIZE.max(MAX_NEXT_SET_SIZE);
    assert_over_max(&with_forms(max + 1)?, ListField::SignatureForms, max)?;
    assert_decodes(&with_forms(max)?)
}

#[test]
fn revealed_keys_over_max_next_set_size_are_rejected() -> TestResult {
    assert_over_max(
        &with_revealed_keys(MAX_NEXT_SET_SIZE + 1)?,
        ListField::RevealedKeys,
        MAX_NEXT_SET_SIZE,
    )?;
    assert_decodes(&with_revealed_keys(MAX_NEXT_SET_SIZE)?)
}

#[test]
fn installed_root_set_over_max_root_set_size_is_rejected() -> TestResult {
    assert_over_max(
        &with_root_members(MAX_ROOT_SET_SIZE + 1)?,
        ListField::InstalledRootSet,
        MAX_ROOT_SET_SIZE,
    )?;
    assert_decodes(&with_root_members(MAX_ROOT_SET_SIZE)?)
}

#[test]
fn witness_set_over_max_witness_set_size_is_rejected() -> TestResult {
    assert_over_max(
        &with_witnesses(MAX_WITNESS_SET_SIZE + 1)?,
        ListField::Witnesses,
        MAX_WITNESS_SET_SIZE,
    )?;
    assert_decodes(&with_witnesses(MAX_WITNESS_SET_SIZE)?)
}

#[test]
fn commitment_list_over_max_next_set_size_is_rejected() -> TestResult {
    assert_over_max(
        &with_commitments(MAX_NEXT_SET_SIZE + 1)?,
        ListField::Commitments,
        MAX_NEXT_SET_SIZE,
    )?;
    assert_decodes(&with_commitments(MAX_NEXT_SET_SIZE)?)
}

#[test]
fn a_count_of_u32_max_is_rejected_before_any_allocation() -> TestResult {
    // §9.7.4.2's own example: a snapshot key count of 0xFFFFFFFF. The
    // snapshot key list has no MAX_*, so the remaining bytes bound it.
    let mut bytes = v41_fields()?;
    bytes
        .get_mut(KEY_COUNT..KEY_COUNT + 4)
        .ok_or("short")?
        .copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        decode_preimage(&bytes),
        Err(DecodeError::CountOverRemaining {
            list: ListField::SnapshotKeys,
            count: u32::MAX,
            remaining: V41_FIELD_LEN - KEY_COUNT - 4,
        })
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The count-bound rule: each list's count one byte past the bytes remaining.
// ---------------------------------------------------------------------------

/// Cuts `bytes` one byte short of the list whose count sits at `offset`,
/// and asserts the decoder rejects the count before reading an element.
fn assert_over_remaining(
    bytes: &[u8],
    offset: usize,
    element_bytes: usize,
    list: ListField,
) -> TestResult {
    let count = count_at(bytes, offset)?;
    assert!(count > 0, "the list must carry an element to cut");
    let needed = n(count)? * element_bytes;
    let cut = bytes.get(..offset + 4 + needed - 1).ok_or("short")?;
    assert_eq!(
        decode_preimage(cut),
        Err(DecodeError::CountOverRemaining {
            list,
            count,
            remaining: needed - 1,
        })
    );
    Ok(())
}

#[test]
fn signer_index_list_past_the_remaining_bytes_is_rejected() -> TestResult {
    assert_over_remaining(&v41_fields()?, INDEX_COUNT, 1, ListField::SignerIndices)
}

#[test]
fn signature_form_list_past_the_remaining_bytes_is_rejected() -> TestResult {
    assert_over_remaining(&v41_fields()?, FORM_COUNT, 1, ListField::SignatureForms)
}

#[test]
fn revealed_keys_past_the_remaining_bytes_are_rejected() -> TestResult {
    // A CommitmentRollover: two groups of one index and one form each put
    // the revealed-key count at 74 + 2 * 5 + 2 * 5.
    let rollover = EventPreimage::commitment_rollover(CommitmentRolloverFields {
        identifier: identifier(V41_IDENTIFIER)?,
        sequence: 1,
        predecessor_digest: array(V41_DIGEST)?,
        reveal_group: SignerGroup {
            indices: vec![0],
            forms: vec![SignatureForm::Raw],
        },
        standing_root_group: SignerGroup {
            indices: vec![0],
            forms: vec![SignatureForm::Raw],
        },
        revealed_keys: vec![[2; 33]],
        continuation: Continuation::Abandons,
    });
    assert_over_remaining(
        &encode_preimage(&rollover)?,
        94,
        33,
        ListField::RevealedKeys,
    )
}

#[test]
fn installed_root_set_past_the_remaining_bytes_is_rejected() -> TestResult {
    assert_over_remaining(
        &v41_fields()?,
        ROOT_SET_COUNT,
        33,
        ListField::InstalledRootSet,
    )
}

#[test]
fn snapshot_key_list_past_the_remaining_bytes_is_rejected() -> TestResult {
    assert_over_remaining(&v41_fields()?, KEY_COUNT, 45, ListField::SnapshotKeys)
}

#[test]
fn witness_set_past_the_remaining_bytes_is_rejected() -> TestResult {
    assert_over_remaining(&v41_fields()?, WITNESS_COUNT, 32, ListField::Witnesses)
}

#[test]
fn seals_past_the_remaining_bytes_are_rejected() -> TestResult {
    assert_over_remaining(&fields(V50_PREIMAGE)?, V50_SEAL_COUNT, 32, ListField::Seals)
}

#[test]
fn commitment_list_past_the_remaining_bytes_is_rejected() -> TestResult {
    assert_over_remaining(&v41_fields()?, COMMITMENT_COUNT, 34, ListField::Commitments)
}

// ---------------------------------------------------------------------------
// Length: over MAX_EVENT_BYTES, and truncation inside every fixed field.
// ---------------------------------------------------------------------------

#[test]
fn input_over_max_event_bytes_is_rejected() -> TestResult {
    let len = n(MAX_EVENT_BYTES)? + 1;
    assert_eq!(
        decode_preimage(&vec![0x01; len]),
        Err(DecodeError::EventTooLong { len })
    );
    // At exactly MAX_EVENT_BYTES the length rule passes and parsing runs.
    assert!(!matches!(
        decode_preimage(&vec![0x01; len - 1]),
        Err(DecodeError::EventTooLong { .. })
    ));
    Ok(())
}

macro_rules! truncation_test {
    ($name:ident, $len:expr, $field:expr) => {
        #[test]
        fn $name() -> TestResult {
            let bytes = v41_fields()?;
            assert_eq!(
                decode_preimage(bytes.get(..$len).ok_or("short")?),
                Err(DecodeError::Truncated { field: $field })
            );
            Ok(())
        }
    };
}

truncation_test!(truncated_in_event_type, 0, PreimageField::EventType);
truncation_test!(truncated_in_identifier, 10, PreimageField::Identifier);
truncation_test!(truncated_in_sequence, 35, PreimageField::Sequence);
truncation_test!(
    truncated_in_predecessor_digest,
    50,
    PreimageField::PredecessorDigest
);
truncation_test!(
    truncated_in_standing_root,
    STANDING_ROOT,
    PreimageField::StandingRoot
);
truncation_test!(
    truncated_in_signer_index_count,
    INDEX_COUNT + 2,
    PreimageField::SignerIndices
);
truncation_test!(
    truncated_in_signature_form_count,
    FORM_COUNT + 2,
    PreimageField::SignatureForms
);
truncation_test!(
    truncated_in_revealed_key_count,
    REVEALED_COUNT + 2,
    PreimageField::RevealedKeys
);
truncation_test!(
    truncated_in_root_set_count,
    ROOT_SET_COUNT + 2,
    PreimageField::InstalledRootSet
);
truncation_test!(
    truncated_in_root_set_threshold,
    ROOT_SET_COUNT + 4 + 33 + 2,
    PreimageField::InstalledRootSet
);
truncation_test!(
    truncated_in_snapshot_root_threshold,
    ROOT_SET_COUNT + 4 + 33 + 4 + 2,
    PreimageField::KeyState
);
// A cut inside a key entry fails the count bound first (CountOverRemaining,
// `snapshot_key_list_past_the_remaining_bytes_is_rejected`), since entries
// are fixed-size; the witness count after the entries is the next fixed field.
truncation_test!(
    truncated_in_witness_count,
    WITNESS_COUNT + 2,
    PreimageField::KeyState
);
truncation_test!(
    truncated_in_witnessing_interval,
    SERVICE_KEY_ROLE - 2,
    PreimageField::KeyState
);
truncation_test!(
    truncated_in_service_key_role,
    SERVICE_KEY_ROLE,
    PreimageField::KeyState
);
truncation_test!(
    truncated_in_delegator,
    SERVICE_KEY_ROLE + 10,
    PreimageField::KeyState
);
truncation_test!(
    truncated_in_seal_count,
    SEAL_COUNT + 2,
    PreimageField::Seals
);
truncation_test!(
    truncated_before_continuation,
    CONTINUATION,
    PreimageField::Continuation
);
truncation_test!(
    truncated_in_commitment_count,
    COMMITMENT_COUNT + 2,
    PreimageField::Continuation
);
truncation_test!(
    truncated_in_next_threshold,
    V41_FIELD_LEN - 2,
    PreimageField::Continuation
);

#[test]
fn truncated_continuation_sentinel_is_rejected() -> TestResult {
    // Vector 50 ends in field 12's four-byte sentinel; three zero bytes are
    // neither the sentinel nor the one abandonment byte.
    let bytes = fields(V50_PREIMAGE)?;
    assert_eq!(
        decode_preimage(bytes.get(..bytes.len() - 1).ok_or("short")?),
        Err(DecodeError::Truncated {
            field: PreimageField::Continuation
        })
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Trailing bytes.
// ---------------------------------------------------------------------------

#[test]
fn byte_after_a_commitment_continuation_is_rejected() -> TestResult {
    let mut bytes = v41_fields()?;
    bytes.push(0x00);
    assert_eq!(
        decode_preimage(&bytes),
        Err(DecodeError::TrailingBytes { count: 1 })
    );
    Ok(())
}

#[test]
fn byte_after_the_continuation_sentinel_is_rejected() -> TestResult {
    let mut bytes = fields(V50_PREIMAGE)?;
    bytes.push(0x00);
    assert_eq!(
        decode_preimage(&bytes),
        Err(DecodeError::TrailingBytes { count: 1 })
    );
    Ok(())
}

#[test]
fn byte_after_abandonment_is_rejected() -> TestResult {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    preimage.continuation = Some(Continuation::Abandons);
    let mut bytes = encode_preimage(&preimage)?;
    assert_eq!(bytes.last(), Some(&0x00));
    assert_eq!(decode_preimage(&bytes)?, preimage);
    bytes.push(0x07);
    assert_eq!(
        decode_preimage(&bytes),
        Err(DecodeError::TrailingBytes { count: 1 })
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Unregistered discriminators: the five scp_did-typed fields name the field
// and wrap scp_did::UnknownDiscriminator.
// ---------------------------------------------------------------------------

fn assert_unknown(
    bytes: &[u8],
    field: DiscriminatorField,
    kind: DiscriminatorKind,
    value: u8,
) -> TestResult {
    let error = decode_preimage(bytes).err().ok_or("decoded")?;
    assert_eq!(
        error,
        DecodeError::UnknownDiscriminator {
            field,
            source: UnknownDiscriminator { kind, value },
        }
    );
    assert!(error.to_string().contains(&field.to_string()));
    Ok(())
}

#[test]
fn unregistered_role_names_the_role_field() -> TestResult {
    assert_unknown(
        &v41_with(ENTRY_0 + ROLE, 0x03)?,
        DiscriminatorField::Role,
        DiscriminatorKind::KeyRole,
        0x03,
    )
}

#[test]
fn unregistered_condition_names_the_condition_field() -> TestResult {
    assert_unknown(
        &v41_with(ENTRY_0 + CONDITION, 0x05)?,
        DiscriminatorField::Condition,
        DiscriminatorKind::KeyCondition,
        0x05,
    )
}

#[test]
fn unregistered_custody_type_names_the_custody_type_field() -> TestResult {
    assert_unknown(
        &v41_with(ENTRY_1 + CUSTODY, 0x0a)?,
        DiscriminatorField::CustodyType,
        DiscriminatorKind::CustodyType,
        0x0a,
    )?;
    // The continuation's commitment entries carry the same field.
    assert_unknown(
        &v41_with(COMMITMENT_CUSTODY, 0x00)?,
        DiscriminatorField::CustodyType,
        DiscriminatorKind::CustodyType,
        0x00,
    )
}

#[test]
fn unregistered_key_algorithm_names_the_key_algorithm_field() -> TestResult {
    assert_unknown(
        &v41_with(ENTRY_0 + ALGORITHM, 0x02)?,
        DiscriminatorField::KeyAlgorithm,
        DiscriminatorKind::KeyAlgorithm,
        0x02,
    )?;
    assert_unknown(
        &v41_with(COMMITMENT_ALGORITHM, 0x02)?,
        DiscriminatorField::KeyAlgorithm,
        DiscriminatorKind::KeyAlgorithm,
        0x02,
    )
}

#[test]
fn unregistered_service_key_role_names_the_service_key_role_field() -> TestResult {
    assert_unknown(
        &v41_with(SERVICE_KEY_ROLE, 0x03)?,
        DiscriminatorField::ServiceKeyRole,
        DiscriminatorKind::KeyRole,
        0x03,
    )
}

fn assert_unknown_event_byte(
    offset: usize,
    value: u8,
    field: EventDiscriminatorField,
) -> TestResult {
    assert_eq!(
        decode_preimage(&v41_with(offset, value)?),
        Err(DecodeError::UnknownEventDiscriminator { field, value })
    );
    Ok(())
}

#[test]
fn unregistered_event_type_is_rejected() -> TestResult {
    assert_unknown_event_byte(KIND, 0x05, EventDiscriminatorField::EventType)?;
    assert_unknown_event_byte(KIND, 0x00, EventDiscriminatorField::EventType)
}

#[test]
fn unregistered_standing_root_is_rejected() -> TestResult {
    assert_unknown_event_byte(STANDING_ROOT, 0x03, EventDiscriminatorField::StandingRoot)
}

#[test]
fn unregistered_signature_form_is_rejected() -> TestResult {
    assert_unknown_event_byte(FORM, 0x03, EventDiscriminatorField::SignatureForm)?;
    assert_unknown_event_byte(FORM, 0x00, EventDiscriminatorField::SignatureForm)
}

#[test]
fn unregistered_continuation_byte_is_rejected() -> TestResult {
    assert_unknown_event_byte(CONTINUATION, 0x02, EventDiscriminatorField::Continuation)
}

#[test]
fn root_recovery_without_a_standing_root_declaration_is_rejected() -> TestResult {
    assert_eq!(
        decode_preimage(&v41_with(KIND, 0x04)?),
        Err(DecodeError::RootRecoveryWithoutStandingRoot)
    );
    Ok(())
}

#[test]
fn decoder_leaves_kind_versus_field_legality_to_the_verifier() -> TestResult {
    // Vector 41's fields under the KeyState kind byte: a KeyState carrying
    // an installed root set and a continuation is an R3 defect, which the
    // verifier classifies; the decoder hands it over intact.
    let decoded = decode_preimage(&v41_with(KIND, 0x02)?)?;
    let mut expected = v41_inception(SignatureForm::Raw)?;
    expected.kind = EventKind::KeyState;
    assert_eq!(decoded, expected);
    Ok(())
}

// ---------------------------------------------------------------------------
// `compromised_from`: "the position a `Compromised` entry carries and zero
// otherwise" (09-security-model.md §9.7.4.2, the key-state snapshot's order).
// ---------------------------------------------------------------------------

fn v41_entry_with(
    entry: usize,
    condition: u8,
    compromised_from: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = v41_with(entry + CONDITION, condition)?;
    bytes
        .get_mut(entry + COMPROMISED_FROM..entry + CUSTODY)
        .ok_or("short")?
        .copy_from_slice(&compromised_from.to_be_bytes());
    Ok(bytes)
}

fn assert_compromised_from_rejected(condition: KeyCondition) -> TestResult {
    assert_eq!(
        decode_preimage(&v41_entry_with(ENTRY_1, condition.to_byte(), 7)?),
        Err(DecodeError::CompromisedFromWithoutCompromise {
            entry: 1,
            condition,
            compromised_from: 7,
        })
    );
    Ok(())
}

#[test]
fn current_entry_with_nonzero_compromised_from_is_rejected() -> TestResult {
    assert_compromised_from_rejected(KeyCondition::Current)
}

#[test]
fn superseded_entry_with_nonzero_compromised_from_is_rejected() -> TestResult {
    assert_compromised_from_rejected(KeyCondition::Superseded)
}

#[test]
fn retired_entry_with_nonzero_compromised_from_is_rejected() -> TestResult {
    assert_compromised_from_rejected(KeyCondition::Retired)
}

#[test]
fn compromised_entry_decodes_at_any_position_including_zero() -> TestResult {
    // §9.7.4.2 states no decode rule for a Compromised entry's position:
    // position 0 exists, and R8's bound against the event's sequence is a
    // verifier rule.
    for position in [0, 1, u64::MAX] {
        let decoded = decode_preimage(&v41_entry_with(
            ENTRY_0,
            KeyCondition::Compromised.to_byte(),
            position,
        )?)?;
        let entry = decoded
            .key_state
            .as_ref()
            .and_then(|snapshot| snapshot.keys.first())
            .ok_or("no entry")?;
        assert_eq!(entry.condition, KeyCondition::Compromised);
        assert_eq!(entry.compromised_from, position);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The encoder refuses what would not decode back.
// ---------------------------------------------------------------------------

#[test]
fn encoder_rejects_nonzero_compromised_from_without_compromise() -> TestResult {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    let snapshot = preimage.key_state.as_mut().ok_or("no snapshot")?;
    snapshot.keys.get_mut(1).ok_or("no entry")?.compromised_from = 3;
    assert_eq!(
        encode_preimage(&preimage),
        Err(EncodeError::CompromisedFromWithoutCompromise {
            entry: 1,
            condition: KeyCondition::Current,
            compromised_from: 3,
        })
    );
    Ok(())
}

#[test]
fn encoder_rejects_values_that_would_encode_as_a_sentinel() -> TestResult {
    let mut empty_root = v41_inception(SignatureForm::Raw)?;
    empty_root
        .installed_root_set
        .as_mut()
        .ok_or("no root set")?
        .members
        .clear();
    assert_eq!(
        encode_preimage(&empty_root),
        Err(EncodeError::EmptyInstalledRootSet)
    );

    let mut zero_threshold = v41_inception(SignatureForm::Raw)?;
    zero_threshold
        .key_state
        .as_mut()
        .ok_or("no snapshot")?
        .root_threshold = 0;
    assert_eq!(
        encode_preimage(&zero_threshold),
        Err(EncodeError::ZeroRootThreshold)
    );
    Ok(())
}

#[test]
fn encoder_rejects_a_signer_group_count_the_kind_does_not_name() -> TestResult {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    preimage.signer_groups.push(SignerGroup {
        indices: vec![0],
        forms: vec![SignatureForm::Raw],
    });
    assert_eq!(
        encode_preimage(&preimage),
        Err(EncodeError::SignerGroupCount {
            kind: EventKind::Inception,
            expected: 1,
            actual: 2,
        })
    );

    let mut recovery = v41_inception(SignatureForm::Raw)?;
    recovery.kind = EventKind::RootRecovery;
    assert_eq!(
        encode_preimage(&recovery),
        Err(EncodeError::RootRecoveryWithoutStandingRoot)
    );
    Ok(())
}
