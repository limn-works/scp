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
    CommitmentRolloverFields, Continuation, DecodeError, DidDiscriminatorField, EncodeError,
    EventKind, EventPreimage, KelDiscriminatorField, ListField, PreimageField, RootRecoveryFields,
    SignatureForm, SignerGroup, SignerGroupRole, StandingRootSigning, decode_preimage,
    encode_preimage,
};

use crate::fixtures::{
    TestResult, V41_DIGEST, V41_IDENTIFIER, V41_PREIMAGE, V50_PREIMAGE, array, bytes, fields,
    identifier, v41_inception, v41_snapshot, v50_key_state,
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
// The count-bound rule (§9.7.4.2): a list is capped by the `MAX_*` §9.18.17
// registers for it and otherwise only by the bytes remaining. Every count
// here is written into the bytes, never through the encoder, so the decoder
// is tested on wire input the encoder could not produce. Every list that
// decodes re-encodes to the identical bytes.
// ---------------------------------------------------------------------------

fn n(count: u32) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(usize::try_from(count)?)
}

/// Replaces the list whose count sits at `offset` in `bytes` (holding
/// `old` elements of `element.len()` bytes) with `count` copies of
/// `element`, writing the count directly.
fn splice_list(
    bytes: &[u8],
    offset: usize,
    old: usize,
    element: &[u8],
    count: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let end = offset + 4 + old * element.len();
    let mut out = bytes.get(..offset).ok_or("offset past the end")?.to_vec();
    out.extend_from_slice(&count.to_be_bytes());
    for _ in 0..count {
        out.extend_from_slice(element);
    }
    out.extend_from_slice(bytes.get(end..).ok_or("list past the end")?);
    Ok(out)
}

/// Asserts `bytes` decode and re-encode to the identical bytes.
fn assert_decodes_identically(bytes: &[u8]) -> TestResult {
    let decoded = decode_preimage(bytes)?;
    assert_eq!(encode_preimage(decoded.preimage())?.fields(), bytes);
    Ok(())
}

/// Asserts the list at `offset` decodes at `max` and is rejected at
/// `max + 1`, with an error that names the list.
fn assert_capped(
    bytes: &[u8],
    offset: usize,
    old: usize,
    element: &[u8],
    list: ListField,
    max: u32,
) -> TestResult {
    assert_decodes_identically(&splice_list(bytes, offset, old, element, max)?)?;
    let error = decode_preimage(&splice_list(bytes, offset, old, element, max + 1)?)
        .err()
        .ok_or("a list over its maximum decoded")?;
    assert_eq!(
        error,
        DecodeError::CountOverMax {
            list,
            count: max + 1,
            max
        }
    );
    assert!(error.to_string().contains(&list.to_string()));
    Ok(())
}

/// Asserts the list at `offset` decodes with `count` entries, past every
/// registered maximum: §9.18.17 registers none for it.
fn assert_uncapped(
    bytes: &[u8],
    offset: usize,
    old: usize,
    element: &[u8],
    count: u32,
) -> TestResult {
    assert_decodes_identically(&splice_list(bytes, offset, old, element, count)?)
}

/// One past the largest registered list maximum.
const PAST_EVERY_CAP: u32 = MAX_WITNESS_SET_SIZE + 1;

fn group() -> SignerGroup {
    SignerGroup {
        indices: vec![0],
        forms: vec![SignatureForm::Raw],
    }
}

/// A `CommitmentRollover`'s field bytes: two groups (reveal, then standing
/// root) of one index and one form each, so field 6's counts sit at 74 and
/// 79, field 7's at 84 and 89, and the revealed-key count at 94.
fn rollover_fields() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let rollover = EventPreimage::commitment_rollover(CommitmentRolloverFields {
        identifier: identifier(V41_IDENTIFIER)?,
        sequence: 1,
        predecessor_digest: array(V41_DIGEST)?,
        reveal_group: group(),
        standing_root_group: group(),
        revealed_keys: vec![[2; 33]],
        continuation: Continuation::Abandons,
    });
    let bytes = encode_preimage(&rollover)?.fields().to_vec();
    for offset in [74, 79, 84, 89, 94] {
        assert_eq!(count_at(&bytes, offset)?, 1);
    }
    Ok(bytes)
}

/// A co-signed `RootRecovery`'s field bytes: three groups (reveal, K′,
/// standing root) of one index and one form each, so field 6's counts sit
/// at 74, 79 and 84, and field 7's at 89, 94 and 99.
fn root_recovery_fields() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let recovery = EventPreimage::root_recovery(RootRecoveryFields {
        identifier: identifier(V41_IDENTIFIER)?,
        sequence: 1,
        predecessor_digest: array(V41_DIGEST)?,
        standing_root_signing: StandingRootSigning::CoSigns {
            standing_root_group: group(),
        },
        reveal_group: group(),
        replacement_root_group: group(),
        revealed_keys: vec![[2; 33]],
        key_state: v41_snapshot(3600)?,
        continuation: Continuation::Abandons,
    });
    let bytes = encode_preimage(&recovery)?.fields().to_vec();
    for offset in [74, 79, 84, 89, 94, 99] {
        assert_eq!(count_at(&bytes, offset)?, 1);
    }
    Ok(bytes)
}

#[test]
fn reveal_group_index_list_is_capped_at_max_next_set_size() -> TestResult {
    let list = ListField::SignerIndices(SignerGroupRole::Reveal);
    assert_capped(&rollover_fields()?, 74, 1, &[0], list, MAX_NEXT_SET_SIZE)?;
    // The reveal group leads a RootRecovery too.
    assert_capped(
        &root_recovery_fields()?,
        74,
        1,
        &[0],
        list,
        MAX_NEXT_SET_SIZE,
    )
}

#[test]
fn installed_root_set_is_capped_at_max_root_set_size() -> TestResult {
    assert_capped(
        &v41_fields()?,
        ROOT_SET_COUNT,
        1,
        &[3; 33],
        ListField::InstalledRootSet,
        MAX_ROOT_SET_SIZE,
    )
}

#[test]
fn witness_set_is_capped_at_max_witness_set_size() -> TestResult {
    assert_capped(
        &v41_fields()?,
        WITNESS_COUNT,
        1,
        &[9; 32],
        ListField::Witnesses,
        MAX_WITNESS_SET_SIZE,
    )
}

#[test]
fn commitment_list_is_capped_at_max_next_set_size() -> TestResult {
    let mut entry = vec![4; 32];
    entry.extend_from_slice(&[
        CustodyType::Software.to_byte(),
        KeyAlgorithm::EcdsaP256Sha256.to_byte(),
    ]);
    assert_capped(
        &v41_fields()?,
        COMMITMENT_COUNT,
        1,
        &entry,
        ListField::Commitments,
        MAX_NEXT_SET_SIZE,
    )
}

#[test]
fn a_17_index_root_group_decodes() -> TestResult {
    assert_uncapped(&v41_fields()?, INDEX_COUNT, 1, &[0], 17)?;
    assert_uncapped(&v41_fields()?, INDEX_COUNT, 1, &[0], PAST_EVERY_CAP)
}

#[test]
fn a_17_entry_form_list_decodes() -> TestResult {
    assert_uncapped(&v41_fields()?, FORM_COUNT, 1, &[0x02], 17)?;
    // Every role's form list: a rollover's two and a recovery's three.
    for offset in [84, 89] {
        assert_uncapped(&rollover_fields()?, offset, 1, &[0x01], PAST_EVERY_CAP)?;
    }
    for offset in [89, 94, 99] {
        assert_uncapped(&root_recovery_fields()?, offset, 1, &[0x01], PAST_EVERY_CAP)?;
    }
    Ok(())
}

#[test]
fn every_index_list_but_the_reveal_groups_is_uncapped() -> TestResult {
    // The rollover's standing-root group, and the recovery's K′ and
    // standing-root groups.
    assert_uncapped(&rollover_fields()?, 79, 1, &[0], PAST_EVERY_CAP)?;
    for offset in [79, 84] {
        assert_uncapped(&root_recovery_fields()?, offset, 1, &[0], PAST_EVERY_CAP)?;
    }
    Ok(())
}

#[test]
fn revealed_keys_snapshot_keys_and_seals_are_uncapped() -> TestResult {
    assert_uncapped(&v41_fields()?, REVEALED_COUNT, 0, &[2; 33], PAST_EVERY_CAP)?;
    let entry = v41_fields()?.get(ENTRY_0..ENTRY_1).ok_or("short")?.to_vec();
    assert_uncapped(&v41_fields()?, KEY_COUNT, 2, &entry, PAST_EVERY_CAP)?;
    assert_uncapped(
        &fields(V50_PREIMAGE)?,
        V50_SEAL_COUNT,
        1,
        &[5; 32],
        PAST_EVERY_CAP,
    )
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
// The encoder reads the same table: a capped list over its maximum is
// refused before any bytes leave, naming the list.
// ---------------------------------------------------------------------------

fn assert_encode_over_max(preimage: &EventPreimage, list: ListField, max: u32) -> TestResult {
    let error = encode_preimage(preimage)
        .err()
        .ok_or("a list over its maximum encoded")?;
    assert_eq!(
        error,
        EncodeError::CountOverMax {
            list,
            len: n(max)? + 1,
            max
        }
    );
    assert!(error.to_string().contains(&list.to_string()));
    Ok(())
}

#[test]
fn encoder_refuses_each_capped_list_over_its_maximum() -> TestResult {
    let over_next = n(MAX_NEXT_SET_SIZE)? + 1;
    let rollover = EventPreimage::commitment_rollover(CommitmentRolloverFields {
        identifier: identifier(V41_IDENTIFIER)?,
        sequence: 1,
        predecessor_digest: array(V41_DIGEST)?,
        reveal_group: SignerGroup {
            indices: vec![0; over_next],
            ..group()
        },
        standing_root_group: group(),
        revealed_keys: Vec::new(),
        continuation: Continuation::Abandons,
    });
    assert_encode_over_max(
        &rollover,
        ListField::SignerIndices(SignerGroupRole::Reveal),
        MAX_NEXT_SET_SIZE,
    )?;

    let mut root_set = v41_inception(SignatureForm::Raw)?;
    root_set
        .installed_root_set
        .as_mut()
        .ok_or("no root set")?
        .members = vec![[3; 33]; n(MAX_ROOT_SET_SIZE)? + 1];
    assert_encode_over_max(&root_set, ListField::InstalledRootSet, MAX_ROOT_SET_SIZE)?;

    let mut witnesses = v41_inception(SignatureForm::Raw)?;
    witnesses.key_state.as_mut().ok_or("no snapshot")?.witnesses =
        vec![Identifier::from_bytes([9; 32]); n(MAX_WITNESS_SET_SIZE)? + 1];
    assert_encode_over_max(&witnesses, ListField::Witnesses, MAX_WITNESS_SET_SIZE)?;

    let mut commitments = v41_inception(SignatureForm::Raw)?;
    let Some(Continuation::FixesCommitment(commitment)) = commitments.continuation.as_mut() else {
        return Err("Vector 41 fixes a commitment".into());
    };
    commitment.commitments = vec![
        CommitmentEntry {
            commitment: [4; 32],
            custody_type: CustodyType::Software,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        };
        over_next
    ];
    assert_encode_over_max(&commitments, ListField::Commitments, MAX_NEXT_SET_SIZE)
}

#[test]
fn encoder_accepts_uncapped_lists_past_every_maximum() -> TestResult {
    let past = n(PAST_EVERY_CAP)?;
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    let root_group = preimage.signer_groups.first_mut().ok_or("no group")?;
    root_group.indices = vec![0; past];
    root_group.forms = vec![SignatureForm::Raw; past];
    preimage.revealed_keys = vec![[2; 33]; past];
    preimage.seals = vec![[5; 32]; past];
    let encoded = encode_preimage(&preimage)?;
    assert_eq!(decode_preimage(encoded.fields())?.preimage(), &preimage);
    Ok(())
}

#[test]
fn encoder_refuses_field_bytes_over_max_event_bytes() -> TestResult {
    // Vector 50's 303 field bytes carry one seal; each further seal adds 32.
    // 2,039 seals end at 65,519 bytes, under MAX_EVENT_BYTES; 2,040 at 65,551.
    let mut preimage = v50_key_state()?;
    preimage.seals = vec![[5; 32]; 2039];
    let encoded = encode_preimage(&preimage)?;
    assert!(encoded.fields().len() <= n(MAX_EVENT_BYTES)?);
    assert_decodes_identically(encoded.fields())?;
    preimage.seals.push([5; 32]);
    assert_eq!(
        encode_preimage(&preimage),
        Err(EncodeError::PreimageTooLong { len: 65_551 })
    );
    Ok(())
}

#[test]
fn decoder_refuses_the_signed_preimage_naming_the_separator() -> TestResult {
    let error = decode_preimage(&bytes(V41_PREIMAGE)?)
        .err()
        .ok_or("the signed preimage decoded")?;
    assert_eq!(error, DecodeError::SignedPreimage);
    assert!(error.to_string().contains("SCP-KEL-EVENT-V1:"));
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
    assert_over_remaining(
        &v41_fields()?,
        INDEX_COUNT,
        1,
        ListField::SignerIndices(SignerGroupRole::Root),
    )
}

#[test]
fn signature_form_list_past_the_remaining_bytes_is_rejected() -> TestResult {
    assert_over_remaining(
        &v41_fields()?,
        FORM_COUNT,
        1,
        ListField::SignatureForms(SignerGroupRole::Root),
    )
}

#[test]
fn revealed_keys_past_the_remaining_bytes_are_rejected() -> TestResult {
    assert_over_remaining(&rollover_fields()?, 94, 33, ListField::RevealedKeys)
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
        Err(DecodeError::PreimageTooLong { len })
    );
    // At exactly MAX_EVENT_BYTES the length rule passes and parsing runs.
    assert!(!matches!(
        decode_preimage(&vec![0x01; len - 1]),
        Err(DecodeError::PreimageTooLong { .. })
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
    let mut bytes = encode_preimage(&preimage)?.fields().to_vec();
    assert_eq!(bytes.last(), Some(&0x00));
    assert_eq!(decode_preimage(&bytes)?.preimage(), &preimage);
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
    field: DidDiscriminatorField,
    kind: DiscriminatorKind,
    value: u8,
) -> TestResult {
    let error = decode_preimage(bytes).err().ok_or("decoded")?;
    assert_eq!(
        error,
        DecodeError::UnknownDidDiscriminator {
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
        DidDiscriminatorField::Role,
        DiscriminatorKind::KeyRole,
        0x03,
    )
}

#[test]
fn unregistered_condition_names_the_condition_field() -> TestResult {
    assert_unknown(
        &v41_with(ENTRY_0 + CONDITION, 0x05)?,
        DidDiscriminatorField::Condition,
        DiscriminatorKind::KeyCondition,
        0x05,
    )
}

#[test]
fn unregistered_custody_type_names_the_custody_type_field() -> TestResult {
    assert_unknown(
        &v41_with(ENTRY_1 + CUSTODY, 0x0a)?,
        DidDiscriminatorField::CustodyType,
        DiscriminatorKind::CustodyType,
        0x0a,
    )?;
    // The continuation's commitment entries carry the same field.
    assert_unknown(
        &v41_with(COMMITMENT_CUSTODY, 0x00)?,
        DidDiscriminatorField::CustodyType,
        DiscriminatorKind::CustodyType,
        0x00,
    )
}

#[test]
fn unregistered_key_algorithm_names_the_key_algorithm_field() -> TestResult {
    assert_unknown(
        &v41_with(ENTRY_0 + ALGORITHM, 0x02)?,
        DidDiscriminatorField::KeyAlgorithm,
        DiscriminatorKind::KeyAlgorithm,
        0x02,
    )?;
    assert_unknown(
        &v41_with(COMMITMENT_ALGORITHM, 0x02)?,
        DidDiscriminatorField::KeyAlgorithm,
        DiscriminatorKind::KeyAlgorithm,
        0x02,
    )
}

#[test]
fn unregistered_service_key_role_names_the_service_key_role_field() -> TestResult {
    assert_unknown(
        &v41_with(SERVICE_KEY_ROLE, 0x03)?,
        DidDiscriminatorField::ServiceKeyRole,
        DiscriminatorKind::KeyRole,
        0x03,
    )
}

fn assert_unknown_event_byte(offset: usize, value: u8, field: KelDiscriminatorField) -> TestResult {
    assert_eq!(
        decode_preimage(&v41_with(offset, value)?),
        Err(DecodeError::UnknownKelDiscriminator { field, value })
    );
    Ok(())
}

#[test]
fn unregistered_event_type_is_rejected() -> TestResult {
    assert_unknown_event_byte(KIND, 0x05, KelDiscriminatorField::EventType)?;
    assert_unknown_event_byte(KIND, 0x00, KelDiscriminatorField::EventType)
}

#[test]
fn unregistered_standing_root_is_rejected() -> TestResult {
    assert_unknown_event_byte(STANDING_ROOT, 0x03, KelDiscriminatorField::StandingRoot)
}

#[test]
fn unregistered_signature_form_is_rejected() -> TestResult {
    assert_unknown_event_byte(FORM, 0x03, KelDiscriminatorField::SignatureForm)?;
    assert_unknown_event_byte(FORM, 0x00, KelDiscriminatorField::SignatureForm)
}

#[test]
fn unregistered_continuation_byte_is_rejected() -> TestResult {
    assert_unknown_event_byte(CONTINUATION, 0x02, KelDiscriminatorField::Continuation)
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
    assert_eq!(decoded.preimage(), &expected);
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
            .preimage()
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
