//! `decode_event` (`09-security-model.md` §9.7.4.2, the check order;
//! §9.10.12) and the encoded-length ceiling (§9.18.17 `MAX_EVENT_BYTES`):
//! one test per stage outcome, the spec 25 round trips, the raw identifier,
//! the inception zero checks, and `MAX_EVENT_BYTES` on both the encoder and
//! the decoder. Each negative test mutates one byte or one length of a spec
//! 25 event unit. Every expected identifier and digest is a §25 constant or
//! a SHA-256 this file computes, never a value scp-kel returns.

use scp_kel::constants::MAX_EVENT_BYTES;
use scp_kel::{
    DecodeError, EncodeError, EventPreimage, EventUnit, HeaderError, InceptionHeaderDefect,
    IndexedSignaturePart, IndexedSignatureReadError, KelDiscriminatorField, ListField,
    SignatureFieldError, SignatureForm, SignerGroup, SignerGroupRole, decode_event,
    decode_preimage, encode_preimage, inception_header_zero_checks, raw_identifier,
};
use sha2::{Digest, Sha256};

use crate::fixtures::{
    SEPARATOR_LEN, TestResult, V41_DIGEST, V41_IDENTIFIER, V41_PREIMAGE, V41_SIGNATURE,
    V42_AUTHENTICATOR_DATA, V42_CLIENT_DATA_JSON_HEX, V42_DIGEST, V42_IDENTIFIER,
    V42_INDEXED_SIGNATURE, V42_PREIMAGE, V50_DIGEST, V50_PREIMAGE, V50_SIGNATURE, V51_DIGEST,
    V51_INCEPTION_DIGEST, V51_INCEPTION_PREIMAGE, V51_INCEPTION_SIGNATURE, V51_PREIMAGE,
    V51_SIGNATURE, V53_DIGEST, V53_PREIMAGE, V53_SIGNATURE_FIELD, V54_DIGEST, V54_PREIMAGE,
    V54_SIGNATURE_FIELD, V55_DIGEST, V55_PREIMAGE, V55_SIGNATURE_FIELD, V68_DIGEST, V68_PREIMAGE,
    V68_REVEAL_SIGNATURE, V68_ROOT_SIGNATURE, V69_DIGEST, V69_PREIMAGE, V69_ROOT_SIGNATURE,
    assert_event_round_trip, bytes, event_unit, identifier, stage, v41_inception, v50_key_state,
    v51_inception, v51_key_state, v68_rollover, v69_key_state,
};

type Error = Box<dyn std::error::Error>;

/// The 4-byte preimage length prefix that opens every event unit.
const PREFIX: usize = 4;
/// Where a unit's field bytes start: the prefix, then the separator.
const FIELDS: usize = PREFIX + SEPARATOR_LEN;
// Offsets into the field bytes, from §9.7.4.2's field order.
const KIND: usize = 0;
const IDENTIFIER: usize = 1;
const SEQUENCE: usize = 33;
const PREDECESSOR: usize = 41;
const STANDING_ROOT: usize = 73;
/// The first signer group's index count, field 6.
const FIRST_INDEX_COUNT: usize = 74;
/// Vector 41's one form byte: after its index count and one index, and its
/// form count.
const V41_FORM: usize = 83;
/// Vector 41's first key entry's role byte, in field 10: the entry starts
/// at 137 and its 33-byte key precedes the role.
const V41_ENTRY_0_ROLE: usize = 137 + 33;
/// The ceilings §9.18.17 reserves for one indexed signature of each form.
const RAW_CEILING: usize = 64;
const ASSERTION_CEILING: usize = 840;

fn max_event_bytes() -> Result<usize, Error> {
    Ok(usize::try_from(MAX_EVENT_BYTES)?)
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `SHA-256("SCP-KEL-ID-V1:" ‖ raw)`, computed here.
fn expected_raw_identifier(raw: &[u8]) -> [u8; 32] {
    sha256(&[b"SCP-KEL-ID-V1:", raw])
}

fn v41_unit() -> Result<Vec<u8>, Error> {
    event_unit(V41_PREIMAGE, V41_SIGNATURE)
}

fn v42_unit() -> Result<Vec<u8>, Error> {
    event_unit(V42_PREIMAGE, V42_INDEXED_SIGNATURE)
}

/// A unit over an encoded preimage's signed bytes and a signature field.
fn unit_of(signed: &[u8], signature_field: &[u8]) -> Result<Vec<u8>, Error> {
    let mut unit = u32::try_from(signed.len())?.to_be_bytes().to_vec();
    unit.extend_from_slice(signed);
    unit.extend_from_slice(signature_field);
    Ok(unit)
}

fn set(unit: &mut [u8], at: usize, value: u8) -> TestResult {
    *unit.get_mut(at).ok_or("offset past the unit")? = value;
    Ok(())
}

fn set_be32(unit: &mut [u8], at: usize, value: u32) -> TestResult {
    unit.get_mut(at..at + 4)
        .ok_or("offset past the unit")?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Asserts step 1 failed: no stage ran and the frame ends.
fn assert_step_1_failed(unit: &EventUnit) {
    assert_eq!(unit.raw_signed_preimage(), None);
    assert!(unit.header().is_none());
    assert!(unit.signatures().is_none());
    assert!(unit.body().is_none());
    assert_eq!(unit.consumed(), None);
}

/// Asserts the header stage failed with `error`, and that no later stage ran.
fn assert_header_failed(unit: &EventUnit, error: &HeaderError) {
    assert!(unit.raw_signed_preimage().is_some());
    assert_eq!(unit.header(), Some(Err(error)));
    assert!(unit.signatures().is_none());
    assert!(unit.body().is_none());
    assert_eq!(unit.consumed(), None);
}

/// Asserts the header and the body passed and the walk failed with `error`.
fn assert_walk_failed(unit: &EventUnit, error: &SignatureFieldError) -> TestResult {
    stage(unit.header(), "header")?;
    stage(unit.body(), "body")?;
    assert_eq!(unit.signatures(), Some(Err(error)));
    assert_eq!(unit.consumed(), None);
    Ok(())
}

const fn walk_error(
    role: SignerGroupRole,
    position: usize,
    error: IndexedSignatureReadError,
) -> SignatureFieldError {
    SignatureFieldError {
        role,
        position,
        error,
    }
}

// ---------------------------------------------------------------------------
// Round trips: every stage succeeds on each spec 25 event.
// ---------------------------------------------------------------------------

#[test]
fn vector_41_round_trips() -> TestResult {
    let preimage = assert_event_round_trip(V41_PREIMAGE, V41_DIGEST, V41_SIGNATURE)?;
    assert_eq!(preimage, v41_inception(SignatureForm::Raw)?);
    Ok(())
}

#[test]
fn vector_42_round_trips_walking_the_assertion_form() -> TestResult {
    let preimage = assert_event_round_trip(V42_PREIMAGE, V42_DIGEST, V42_INDEXED_SIGNATURE)?;
    assert_eq!(preimage, v41_inception(SignatureForm::WebAuthnAssertion)?);
    Ok(())
}

#[test]
fn vector_50_round_trips() -> TestResult {
    let preimage = assert_event_round_trip(V50_PREIMAGE, V50_DIGEST, V50_SIGNATURE)?;
    assert_eq!(preimage, v50_key_state()?);
    Ok(())
}

#[test]
fn vector_51_inception_and_key_state_round_trip() -> TestResult {
    let inception = assert_event_round_trip(
        V51_INCEPTION_PREIMAGE,
        V51_INCEPTION_DIGEST,
        V51_INCEPTION_SIGNATURE,
    )?;
    assert_eq!(inception, v51_inception()?);
    let key_state = assert_event_round_trip(V51_PREIMAGE, V51_DIGEST, V51_SIGNATURE)?;
    assert_eq!(key_state, v51_key_state()?);
    Ok(())
}

#[test]
fn vectors_53_54_and_55_round_trip() -> TestResult {
    assert_event_round_trip(V53_PREIMAGE, V53_DIGEST, V53_SIGNATURE_FIELD)?;
    assert_event_round_trip(V54_PREIMAGE, V54_DIGEST, V54_SIGNATURE_FIELD)?;
    assert_event_round_trip(V55_PREIMAGE, V55_DIGEST, V55_SIGNATURE_FIELD)?;
    Ok(())
}

#[test]
fn vectors_68_and_69_round_trip() -> TestResult {
    let reveal_then_root = format!("{V68_REVEAL_SIGNATURE}{V68_ROOT_SIGNATURE}");
    let rollover = assert_event_round_trip(V68_PREIMAGE, V68_DIGEST, &reveal_then_root)?;
    assert_eq!(rollover, v68_rollover()?);
    let key_state = assert_event_round_trip(V69_PREIMAGE, V69_DIGEST, V69_ROOT_SIGNATURE)?;
    assert_eq!(key_state, v69_key_state()?);
    Ok(())
}

/// Two units in one `value`: the second starts where the first's
/// `consumed` ends, and the end of `value` fails step 1.
#[test]
fn consecutive_units_read_at_each_consumed_offset() -> TestResult {
    let first = v41_unit()?;
    let second = event_unit(V50_PREIMAGE, V50_SIGNATURE)?;
    let value = [first.as_slice(), second.as_slice()].concat();
    let unit = decode_event(&value, 0);
    assert_eq!(unit.consumed(), Some(first.len()));
    let next = decode_event(&value, first.len());
    assert_eq!(
        next.raw_signed_preimage(),
        Some(bytes(V50_PREIMAGE)?.as_slice())
    );
    assert_eq!(next.consumed(), Some(second.len()));
    assert_step_1_failed(&decode_event(&value, value.len()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 1 and the stuffed byte.
// ---------------------------------------------------------------------------

#[test]
fn a_prefix_running_past_value_fails_step_1() -> TestResult {
    let unit = v41_unit()?;
    // Three bytes hold no 4-byte prefix.
    assert_step_1_failed(&decode_event(&unit[..3], 0));
    // The prefix declares one byte more than `value` holds after it.
    let preimage_len = bytes(V41_PREIMAGE)?.len();
    assert_step_1_failed(&decode_event(&unit[..PREFIX + preimage_len - 1], 0));
    // A prefix of u32::MAX.
    let mut huge = unit.clone();
    set_be32(&mut huge, 0, u32::MAX)?;
    assert_step_1_failed(&decode_event(&huge, 0));
    // An offset past `value`, and one at usize::MAX.
    assert_step_1_failed(&decode_event(&unit, unit.len() + 1));
    assert_step_1_failed(&decode_event(&unit, usize::MAX));
    Ok(())
}

/// Vector 41's unit followed by one stuffed byte: `consumed` is Vector 41's
/// unit alone, and the stuffed byte, read as the next unit, fails step 1.
#[test]
fn a_stuffed_byte_is_not_consumed_and_fails_as_the_next_unit() -> TestResult {
    let unit = v41_unit()?;
    let mut value = unit.clone();
    value.push(0x00);
    let decoded = decode_event(&value, 0);
    assert_eq!(decoded.consumed(), Some(unit.len()));
    stage(decoded.signatures(), "walk")?;
    assert_step_1_failed(&decode_event(&value, unit.len()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Steps 2 and 4: the header.
// ---------------------------------------------------------------------------

#[test]
fn a_flipped_separator_byte_fails_the_separator_check() -> TestResult {
    for at in [PREFIX, PREFIX + SEPARATOR_LEN - 1] {
        let mut unit = v41_unit()?;
        let byte = *unit.get(at).ok_or("short unit")?;
        set(&mut unit, at, byte ^ 0x01)?;
        assert_header_failed(&decode_event(&unit, 0), &HeaderError::Separator);
    }
    Ok(())
}

#[test]
fn an_unregistered_event_type_fails_the_header() -> TestResult {
    let mut unit = v41_unit()?;
    set(&mut unit, FIELDS + KIND, 0x05)?;
    assert_header_failed(
        &decode_event(&unit, 0),
        &HeaderError::Fields(DecodeError::UnknownKelDiscriminator {
            field: KelDiscriminatorField::EventType,
            value: 0x05,
        }),
    );
    Ok(())
}

#[test]
fn an_unregistered_standing_root_fails_the_header() -> TestResult {
    let mut unit = v41_unit()?;
    set(&mut unit, FIELDS + STANDING_ROOT, 0x03)?;
    assert_header_failed(
        &decode_event(&unit, 0),
        &HeaderError::Fields(DecodeError::UnknownKelDiscriminator {
            field: KelDiscriminatorField::StandingRoot,
            value: 0x03,
        }),
    );
    Ok(())
}

#[test]
fn a_root_recovery_without_standing_root_fails_the_header() -> TestResult {
    let mut unit = event_unit(V54_PREIMAGE, V54_SIGNATURE_FIELD)?;
    set(&mut unit, FIELDS + STANDING_ROOT, 0x00)?;
    assert_header_failed(
        &decode_event(&unit, 0),
        &HeaderError::Fields(DecodeError::RootRecoveryWithoutStandingRoot),
    );
    Ok(())
}

/// A form list shorter, then longer, than its index list. The preimage
/// codec decodes both, and the header refuses them, because the walk has
/// no form for an index or no index for a form.
#[test]
fn a_form_list_whose_length_differs_from_its_index_list_fails_the_header() -> TestResult {
    for forms in [vec![], vec![SignatureForm::Raw, SignatureForm::Raw]] {
        let mut preimage = v41_inception(SignatureForm::Raw)?;
        let group = preimage.signer_groups.first_mut().ok_or("no group")?;
        group.forms.clone_from(&forms);
        let encoded = encode_preimage(&preimage)?;
        decode_preimage(encoded.fields())?;
        let unit = unit_of(encoded.signed_preimage(), &bytes(V41_SIGNATURE)?)?;
        assert_header_failed(
            &decode_event(&unit, 0),
            &HeaderError::FormListLength {
                role: SignerGroupRole::Root,
                indices: 1,
                forms: forms.len(),
            },
        );
    }
    Ok(())
}

#[test]
fn an_unregistered_form_fails_the_header() -> TestResult {
    let mut unit = v41_unit()?;
    set(&mut unit, FIELDS + V41_FORM, 0x03)?;
    assert_header_failed(
        &decode_event(&unit, 0),
        &HeaderError::Fields(DecodeError::UnknownKelDiscriminator {
            field: KelDiscriminatorField::SignatureForm,
            value: 0x03,
        }),
    );
    Ok(())
}

/// Vector 53's reveal group names 17 indices, over `MAX_NEXT_SET_SIZE`.
#[test]
fn a_reveal_index_list_over_its_cap_fails_the_header() -> TestResult {
    let mut unit = event_unit(V53_PREIMAGE, V53_SIGNATURE_FIELD)?;
    set_be32(&mut unit, FIELDS + FIRST_INDEX_COUNT, 17)?;
    assert_header_failed(
        &decode_event(&unit, 0),
        &HeaderError::Fields(DecodeError::CountOverMax {
            list: ListField::SignerIndices(SignerGroupRole::Reveal),
            count: 17,
            max: 16,
        }),
    );
    Ok(())
}

/// A defect in fields 8 to 12 leaves the header and the walk standing: the
/// stages stay apart, so the verifier sees which check failed.
#[test]
fn a_body_defect_leaves_the_header_and_the_walk() -> TestResult {
    let mut unit = v41_unit()?;
    set(&mut unit, FIELDS + V41_ENTRY_0_ROLE, 0x09)?;
    let decoded = decode_event(&unit, 0);
    stage(decoded.header(), "header")?;
    stage(decoded.signatures(), "walk")?;
    assert!(matches!(
        decoded.body(),
        Some(Err(DecodeError::UnknownDidDiscriminator { .. }))
    ));
    assert_eq!(decoded.consumed(), Some(unit.len()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 5: the signature-field walk.
// ---------------------------------------------------------------------------

#[test]
fn a_raw_signature_cut_short_fails_the_walk() -> TestResult {
    let unit = v41_unit()?;
    let short = &unit[..unit.len() - 1];
    assert_walk_failed(
        &decode_event(short, 0),
        &walk_error(
            SignerGroupRole::Root,
            0,
            IndexedSignatureReadError::Truncated {
                part: IndexedSignaturePart::RawSignature,
                remaining: 63,
            },
        ),
    )
}

/// Vector 53 with its standing-root group's signature stripped.
#[test]
fn a_stripped_second_group_fails_the_walk_at_that_group() -> TestResult {
    let unit = event_unit(V53_PREIMAGE, V53_SIGNATURE_FIELD)?;
    let stripped = &unit[..unit.len() - 64];
    assert_walk_failed(
        &decode_event(stripped, 0),
        &walk_error(
            SignerGroupRole::StandingRoot,
            0,
            IndexedSignatureReadError::Truncated {
                part: IndexedSignaturePart::RawSignature,
                remaining: 0,
            },
        ),
    )
}

/// Offsets into Vector 42's unit: the signature field, its
/// `clientDataJSON` length prefix, and the field's length.
struct V42Layout {
    field: usize,
    client_data_len: usize,
    field_len: usize,
}

fn v42_layout() -> Result<V42Layout, Error> {
    let field = PREFIX + bytes(V42_PREIMAGE)?.len();
    let authenticator = bytes(V42_AUTHENTICATOR_DATA)?.len();
    let client_data = bytes(V42_CLIENT_DATA_JSON_HEX)?.len();
    Ok(V42Layout {
        field,
        client_data_len: field + 4 + authenticator,
        field_len: 4 + authenticator + 4 + client_data + 64,
    })
}

fn assert_v42_walk_fails(at: usize, length: u32, error: IndexedSignatureReadError) -> TestResult {
    let mut unit = v42_unit()?;
    set_be32(&mut unit, at, length)?;
    assert_walk_failed(
        &decode_event(&unit, 0),
        &walk_error(SignerGroupRole::Root, 0, error),
    )
}

/// A declared length within its bound that runs past the field.
#[test]
fn an_assertion_length_running_past_the_field_fails_the_walk() -> TestResult {
    let layout = v42_layout()?;
    assert_eq!(v42_unit()?.len(), layout.field + layout.field_len);
    // clientDataJSON declared at its 512-byte bound.
    assert_v42_walk_fails(
        layout.client_data_len,
        512,
        IndexedSignatureReadError::Truncated {
            part: IndexedSignaturePart::ClientDataJson,
            remaining: layout.field_len - (layout.client_data_len + 4 - layout.field),
        },
    )?;
    // authenticatorData declared at its 256-byte bound, with 100 bytes left.
    let mut unit = v42_unit()?;
    set_be32(&mut unit, layout.field, 256)?;
    assert_walk_failed(
        &decode_event(&unit[..layout.field + 4 + 100], 0),
        &walk_error(
            SignerGroupRole::Root,
            0,
            IndexedSignatureReadError::Truncated {
                part: IndexedSignaturePart::AuthenticatorData,
                remaining: 100,
            },
        ),
    )?;
    // The 64-byte signature cut by one byte.
    let unit = v42_unit()?;
    assert_walk_failed(
        &decode_event(&unit[..unit.len() - 1], 0),
        &walk_error(
            SignerGroupRole::Root,
            0,
            IndexedSignatureReadError::Truncated {
                part: IndexedSignaturePart::AssertionSignature,
                remaining: 63,
            },
        ),
    )
}

/// 36 and 257 bytes of `authenticatorData`, 0 and 513 of `clientDataJSON`,
/// each declared in the walked field (§9.18.17).
#[test]
fn each_assertion_length_bound_fails_the_walk() -> TestResult {
    let layout = v42_layout()?;
    for len in [36, 257] {
        assert_v42_walk_fails(
            layout.field,
            len,
            IndexedSignatureReadError::AuthenticatorDataLength {
                len: usize::try_from(len)?,
            },
        )?;
    }
    for len in [0, 513] {
        assert_v42_walk_fails(
            layout.client_data_len,
            len,
            IndexedSignatureReadError::ClientDataJsonLength {
                len: usize::try_from(len)?,
            },
        )?;
    }
    Ok(())
}

/// A group naming 16 indices over an empty signature field fails at its
/// first signature, in each form, with nothing sized from the count.
#[test]
fn sixteen_indices_over_an_empty_signature_field_fail_at_the_first() -> TestResult {
    for (form, part) in [
        (SignatureForm::Raw, IndexedSignaturePart::RawSignature),
        (
            SignatureForm::WebAuthnAssertion,
            IndexedSignaturePart::AuthenticatorDataLength,
        ),
    ] {
        let mut preimage = v50_key_state()?;
        *preimage.signer_groups.first_mut().ok_or("no group")? = SignerGroup {
            indices: (0..16).collect(),
            forms: vec![form; 16],
        };
        let encoded = encode_preimage(&preimage)?;
        let unit = unit_of(encoded.signed_preimage(), &[])?;
        assert_walk_failed(
            &decode_event(&unit, 0),
            &walk_error(
                SignerGroupRole::Root,
                0,
                IndexedSignatureReadError::Truncated { part, remaining: 0 },
            ),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The raw identifier and the inception zero checks.
// ---------------------------------------------------------------------------

#[test]
fn the_raw_identifier_reproduces_vectors_41_and_42() -> TestResult {
    assert_eq!(
        raw_identifier(&bytes(V41_PREIMAGE)?),
        identifier(V41_IDENTIFIER)?
    );
    assert_eq!(
        raw_identifier(&bytes(V42_PREIMAGE)?),
        identifier(V42_IDENTIFIER)?
    );
    Ok(())
}

/// Vector 41's preimage with one byte appended inside its prefix: the body
/// fails to decode, and the raw identifier is still the hash of the bytes
/// received.
#[test]
fn the_raw_identifier_exists_for_an_inception_whose_body_fails() -> TestResult {
    let mut raw = bytes(V41_PREIMAGE)?;
    raw.push(0x00);
    let unit = unit_of(&raw, &bytes(V41_SIGNATURE)?)?;
    let decoded = decode_event(&unit, 0);
    assert_eq!(
        decoded.body(),
        Some(Err(&DecodeError::TrailingBytes { count: 1 }))
    );
    let received = decoded.raw_signed_preimage().ok_or("no raw preimage")?;
    assert_eq!(
        raw_identifier(received).as_bytes(),
        &expected_raw_identifier(&raw)
    );
    assert_ne!(raw_identifier(received), identifier(V41_IDENTIFIER)?);
    Ok(())
}

#[test]
fn the_inception_zero_checks_pass_vectors_41_42_and_51() -> TestResult {
    for preimage in [V41_PREIMAGE, V42_PREIMAGE, V51_INCEPTION_PREIMAGE] {
        inception_header_zero_checks(&bytes(preimage)?)?;
    }
    Ok(())
}

#[test]
fn the_inception_zero_checks_name_each_field() -> TestResult {
    let raw = bytes(V41_PREIMAGE)?;
    let cases = [
        (
            KIND,
            0x02,
            InceptionHeaderDefect::NotInception { value: 0x02 },
        ),
        (IDENTIFIER, 0x01, InceptionHeaderDefect::NonzeroIdentifier),
        (
            IDENTIFIER + 31,
            0x01,
            InceptionHeaderDefect::NonzeroIdentifier,
        ),
        (SEQUENCE + 7, 0x01, InceptionHeaderDefect::NonzeroSequence),
        (PREDECESSOR, 0x01, InceptionHeaderDefect::NonzeroPredecessor),
        (
            PREDECESSOR + 31,
            0x01,
            InceptionHeaderDefect::NonzeroPredecessor,
        ),
    ];
    for (at, value, defect) in cases {
        let mut mutated = raw.clone();
        *mutated
            .get_mut(SEPARATOR_LEN + at)
            .ok_or("short preimage")? = value;
        assert_eq!(inception_header_zero_checks(&mutated), Err(defect));
    }
    assert_eq!(
        inception_header_zero_checks(&bytes(V50_PREIMAGE)?),
        Err(InceptionHeaderDefect::NotInception { value: 0x02 })
    );
    assert_eq!(
        inception_header_zero_checks(&raw[1..]),
        Err(InceptionHeaderDefect::Separator)
    );
    assert_eq!(
        inception_header_zero_checks(&raw[..SEPARATOR_LEN + STANDING_ROOT - 1]),
        Err(InceptionHeaderDefect::Truncated)
    );
    inception_header_zero_checks(&raw[..SEPARATOR_LEN + STANDING_ROOT])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// MAX_EVENT_BYTES: the encoded length on the encoder and the decoder.
// ---------------------------------------------------------------------------

/// Vector 50's `KeyState` with `group` as its root group, its revealed keys
/// and seals sized so the event's encoded length is `encoded_len`: the
/// signed preimage plus `ceiling` for the group. Revealed keys add 33 bytes
/// and seals 32, so some count of each lands on every length past the base.
fn sized_key_state(
    encoded_len: usize,
    group: SignerGroup,
    ceiling: usize,
) -> Result<EventPreimage, Error> {
    let mut preimage = v50_key_state()?;
    *preimage.signer_groups.first_mut().ok_or("no group")? = group;
    preimage.seals.clear();
    let base = encode_preimage(&preimage)?.signed_preimage().len();
    let target = encoded_len - ceiling;
    let extra = target.checked_sub(base).ok_or("target under the base")?;
    let keys = (0..32)
        .find(|keys| extra >= 33 * keys && (extra - 33 * keys) % 32 == 0)
        .ok_or("no key and seal count reaches the target")?;
    preimage.revealed_keys = vec![[2; 33]; keys];
    preimage.seals = vec![[5; 32]; (extra - 33 * keys) / 32];
    Ok(preimage)
}

fn one_index(form: Option<SignatureForm>) -> SignerGroup {
    SignerGroup {
        indices: vec![0],
        forms: form.into_iter().collect(),
    }
}

/// Accepted at exactly `MAX_EVENT_BYTES` and rejected at one byte more, for
/// each form's ceiling, and for an index with no form, counted at 840.
#[test]
fn the_encoder_bounds_the_encoded_length() -> TestResult {
    let max = max_event_bytes()?;
    for (form, ceiling) in [
        (Some(SignatureForm::Raw), RAW_CEILING),
        (Some(SignatureForm::WebAuthnAssertion), ASSERTION_CEILING),
        (None, ASSERTION_CEILING),
    ] {
        let at_max = sized_key_state(max, one_index(form), ceiling)?;
        let encoded = encode_preimage(&at_max)?;
        assert_eq!(encoded.signed_preimage().len() + ceiling, max);
        let over = sized_key_state(max + 1, one_index(form), ceiling)?;
        assert_eq!(
            encode_preimage(&over),
            Err(EncodeError::EventTooLong {
                encoded_len: max + 1
            })
        );
    }
    Ok(())
}

/// The field bytes of `preimage` with one more 32-byte seal, by byte
/// surgery, since the encoder refuses to emit it. A `KeyState`'s field 12
/// is the four-byte sentinel, so the seals end four bytes from the end and
/// their count sits before them.
fn with_one_more_seal(preimage: &EventPreimage) -> Result<Vec<u8>, Error> {
    let mut fields = encode_preimage(preimage)?.fields().to_vec();
    let seals = preimage.seals.len();
    let count_at = fields.len() - 4 - 32 * seals - 4;
    let count = fields.get(count_at..count_at + 4).ok_or("short fields")?;
    assert_eq!(count, u32::try_from(seals)?.to_be_bytes());
    set_be32(&mut fields, count_at, u32::try_from(seals + 1)?)?;
    let end = fields.len() - 4;
    fields.splice(end..end, [5; 32]);
    Ok(fields)
}

#[test]
fn the_decoder_bounds_the_encoded_length() -> TestResult {
    let max = max_event_bytes()?;
    for (form, ceiling) in [
        (SignatureForm::Raw, RAW_CEILING),
        (SignatureForm::WebAuthnAssertion, ASSERTION_CEILING),
    ] {
        // At exactly MAX_EVENT_BYTES every stage decodes.
        let at_max = sized_key_state(max, one_index(Some(form)), ceiling)?;
        let encoded = encode_preimage(&at_max)?;
        assert_eq!(decode_preimage(encoded.fields())?.preimage(), &at_max);
        let unit = unit_of(encoded.signed_preimage(), &[0; 64])?;
        if form == SignatureForm::Raw {
            assert_eq!(decode_event(&unit, 0).consumed(), Some(unit.len()));
        }
        assert_eq!(stage(decode_event(&unit, 0).body(), "body")?, &encoded);

        // One byte over: 31 bytes under, plus one 32-byte seal.
        let under = sized_key_state(max - 31, one_index(Some(form)), ceiling)?;
        let fields = with_one_more_seal(&under)?;
        let over = Err(DecodeError::EventTooLong {
            encoded_len: max + 1,
        });
        assert_eq!(decode_preimage(&fields), over);
        let signed = [b"SCP-KEL-EVENT-V1:".as_slice(), &fields].concat();
        let decoded = decode_event(&unit_of(&signed, &[0; 64])?, 0);
        stage(decoded.header(), "header")?;
        assert_eq!(decoded.body(), Some(over.as_ref()));
    }
    Ok(())
}
