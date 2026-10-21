//! `decode_event` (`09-security-model.md` §9.7.4.2, the check order;
//! §9.10.12) and the encoded-length ceiling (§9.18.17 `MAX_EVENT_BYTES`):
//! one test per stage outcome, the spec 25 round trips with their decoded
//! values, the walk and the form-list check at every group and position of
//! Vector 54's layout, the received preimage's identifier and inception
//! zero checks, `MAX_EVENT_BYTES` at step 4, and every unit of the fuzz
//! seed corpus. Each negative test mutates one byte or one length of a spec
//! 25 event unit. Every expected identifier, key and digest is a §25
//! constant or a SHA-256 this file computes, never a value scp-kel returns.

use std::path::Path;

use scp_did::KeyCondition;
use scp_kel::constants::MAX_EVENT_BYTES;
use scp_kel::{
    BodyError, Continuation, DecodeError, EncodeError, EventKind, EventPreimage, EventUnit,
    FormListLength, HeaderDiscriminator, HeaderError, HeaderField, InceptionHeaderDefect,
    IndexedSignaturePart, IndexedSignatureReadError, SignatureFieldError, SignatureForm,
    SignerGroup, SignerGroupRole, SignerList, StandingRootDeclaration, decode_event,
    decode_preimage, encode_preimage,
};
use sha2::{Digest, Sha256};

use crate::fixtures::{
    SEPARATOR_LEN, TestResult, V41_DIGEST, V41_IDENTIFIER, V41_PREIMAGE, V41_ROOT, V41_SIGNATURE,
    V42_AUTHENTICATOR_DATA, V42_CLIENT_DATA_JSON_HEX, V42_DIGEST, V42_IDENTIFIER,
    V42_INDEXED_SIGNATURE, V42_PREIMAGE, V47A_POINT, V47B_POINT, V50_DIGEST, V50_PREIMAGE,
    V50_SIGNATURE, V51_DIGEST, V51_INCEPTION_DIGEST, V51_INCEPTION_PREIMAGE,
    V51_INCEPTION_SIGNATURE, V51_PREIMAGE, V51_SIGNATURE, V53_DIGEST, V53_PREIMAGE,
    V53_SIGNATURE_FIELD, V54_DIGEST, V54_PREIMAGE, V54_SIGNATURE_FIELD, V55_DIGEST, V55_PREIMAGE,
    V55_SIGNATURE_FIELD, V68_DIGEST, V68_PREIMAGE, V68_REVEAL_SIGNATURE, V68_ROOT_SIGNATURE,
    V69_DIGEST, V69_PREIMAGE, V69_ROOT_SIGNATURE, array, assert_event_round_trip, bytes,
    event_unit, fields, identifier, read_unit, v41_inception, v50_key_state, v51_inception,
    v51_key_state, v68_rollover, v69_key_state,
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
/// A one-group event's form count and form: after its index count and one
/// index (Vectors 41 and 50).
const ONE_GROUP_FORM_COUNT: usize = 79;
const V41_FORM: usize = 83;
/// Vector 41's first key entry's role byte, in field 10: the entry starts
/// at 137 and its 33-byte key precedes the role.
const V41_ENTRY_0_ROLE: usize = 137 + 33;
/// The ceilings §9.18.17 reserves for one indexed signature of each form.
const RAW_CEILING: usize = 64;
const ASSERTION_CEILING: usize = 840;

// Spec 25 values Vectors 53 to 55 print that no shared fixture names.
/// Vector 53's next commitment.
const V53_NEXT_COMMITMENT: &str =
    "bf945a74e57e4b861cdba9a78df32004adc443e983e957b9aa9749ade24be4bd";
/// Vector 54's installed K′ member, its `#active` key and next commitment.
const V54_ROOT: &str = "034c3e84e8da62f05b0a280d5a0426e24bde13c6fa023c567333bece3bc1497c53";
const V54_ACTIVE: &str = "026188be77992cb98024f995da162f844f534e4a7f8fca8dc7b1d0cb4b54ce4c64";
const V54_NEXT_COMMITMENT: &str =
    "41def207e7438655edf2766aa2fe0c96ef5f898233fb5ba16c56a3f7765aa8bd";
/// Vector 55's installed K′ member, its `#active` key and next commitment.
const V55_ROOT: &str = "026bf1355bb40ab86b1f3d2e776e08da67e754a5dfeeb706b67d7483d09451c4ce";
const V55_ACTIVE: &str = "03b7fe460356f0d94ff2bb085ed16157ae327b7769f2823ca829077110f05fb4a5";
const V55_NEXT_COMMITMENT: &str =
    "cb05862aec3a89bd73c5e2d10a61d6483d945c72036bdf62dd880a9ff7d4d6f0";

fn max_event_bytes() -> Result<usize, Error> {
    Ok(usize::try_from(MAX_EVENT_BYTES)?)
}

/// An encoded length as the `u64` the header and the errors carry.
fn len64(len: usize) -> Result<u64, Error> {
    Ok(u64::try_from(len)?)
}

/// `SHA-256("SCP-KEL-ID-V1:" ‖ raw)`, computed here.
fn expected_raw_identifier(raw: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-KEL-ID-V1:");
    hasher.update(raw);
    hasher.finalize().into()
}

fn v41_unit() -> Result<Vec<u8>, Error> {
    event_unit(V41_PREIMAGE, V41_SIGNATURE)
}

fn v42_unit() -> Result<Vec<u8>, Error> {
    event_unit(V42_PREIMAGE, V42_INDEXED_SIGNATURE)
}

/// A unit over a signed preimage and a signature field.
fn unit_of(signed: &[u8], signature_field: &[u8]) -> Result<Vec<u8>, Error> {
    let mut unit = u32::try_from(signed.len())?.to_be_bytes().to_vec();
    unit.extend_from_slice(signed);
    unit.extend_from_slice(signature_field);
    Ok(unit)
}

/// A unit over field bytes, behind the separator, and a signature field.
fn unit_of_fields(field_bytes: &[u8], signature_field: &[u8]) -> Result<Vec<u8>, Error> {
    unit_of(
        &[b"SCP-KEL-EVENT-V1:".as_slice(), field_bytes].concat(),
        signature_field,
    )
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

/// Replaces the list whose count sits at `offset` in `bytes`, holding `old`
/// elements of `element.len()` bytes, with `elements`.
fn splice_list(
    bytes: &[u8],
    offset: usize,
    old: usize,
    element_len: usize,
    elements: &[u8],
) -> Result<Vec<u8>, Error> {
    let end = offset + 4 + old * element_len;
    let mut out = bytes.get(..offset).ok_or("offset past the end")?.to_vec();
    out.extend_from_slice(&u32::try_from(elements.len() / element_len)?.to_be_bytes());
    out.extend_from_slice(elements);
    out.extend_from_slice(bytes.get(end..).ok_or("list past the end")?);
    Ok(out)
}

/// Asserts step 1 failed.
fn assert_step_1_failed(value: &[u8], offset: usize) {
    assert_eq!(decode_event(value, offset), EventUnit::Unframed);
}

/// Asserts step 4 failed with `error`.
fn assert_header_failed(unit: &[u8], error: &HeaderError) -> TestResult {
    match decode_event(unit, 0) {
        EventUnit::HeaderFailed(failed) => {
            assert_eq!(failed.error(), error);
            Ok(())
        }
        other => Err(format!("expected a header failure, got {other:?}").into()),
    }
}

/// Asserts the header and the body passed and the walk failed with `error`.
fn assert_walk_failed(unit: &[u8], error: &SignatureFieldError) -> TestResult {
    let read = read_unit(unit)?;
    read.preimage().map_err(Clone::clone)?;
    assert_eq!(read.signature_field(), Err(error));
    Ok(())
}

const fn walk_error(
    role: SignerGroupRole,
    position: usize,
    index: u8,
    error: IndexedSignatureReadError,
) -> SignatureFieldError {
    SignatureFieldError {
        role,
        position,
        index,
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

/// The values one of Vectors 53 to 55 prints for its header, its groups and
/// its body.
struct Layout {
    kind: EventKind,
    standing_root: Option<StandingRootDeclaration>,
    roles: &'static [SignerGroupRole],
    /// The installed K′ member, where the event installs one.
    root: Option<&'static str>,
    /// The snapshot's keys and conditions, in snapshot order.
    keys: &'static [(&'static str, KeyCondition)],
    next_commitment: &'static str,
}

/// Asserts a group-layout vector round-trips (`assert_event_round_trip`,
/// which re-encodes the body), then compares its decoded values with the
/// ones spec 25 prints: each is an event at sequence 1 after Vector 41,
/// whose groups each name member 0 in the raw form, signed in the printed
/// order, and which reveals §25.2's tertiary key and fixes one commitment
/// with next threshold 1.
fn assert_layout(
    preimage_hex: &str,
    digest_hex: &str,
    field_hex: &str,
    layout: &Layout,
) -> TestResult {
    let preimage = assert_event_round_trip(preimage_hex, digest_hex, field_hex)?;
    let read = read_unit(&event_unit(preimage_hex, field_hex)?)?;
    let header = read.header();
    assert_eq!(header.kind(), layout.kind);
    assert_eq!(header.identifier_field(), identifier(V41_IDENTIFIER)?);
    assert_eq!(header.sequence(), 1);
    assert_eq!(header.predecessor_digest(), &array::<32>(V41_DIGEST)?);
    assert_eq!(header.standing_root(), layout.standing_root);
    assert_eq!(
        header.encoded_len(),
        len64(bytes(preimage_hex)?.len() + RAW_CEILING * layout.roles.len())?
    );

    let printed = bytes(field_hex)?;
    let walked: Vec<SignerGroupRole> = read
        .walked_groups()
        .map_err(Clone::clone)?
        .map(|group| group.role())
        .collect();
    assert_eq!(walked, layout.roles);
    for (group, printed) in read
        .walked_groups()
        .map_err(Clone::clone)?
        .zip(printed.chunks(RAW_CEILING))
    {
        let [signer] = group.group().signers() else {
            return Err("each group names one signer".into());
        };
        assert_eq!((signer.index(), signer.form()), (0, SignatureForm::Raw));
        let [signature] = group.signatures() else {
            return Err("each group carries one signature".into());
        };
        assert_eq!(signature.index(), 0);
        assert_eq!(signature.signature().form(), SignatureForm::Raw);
        assert_eq!(signature.signature().to_bytes(), printed);
    }

    assert_eq!(preimage.revealed_keys, vec![array::<33>(V47A_POINT)?]);
    match layout.root {
        None => assert_eq!(preimage.installed_root_set, None),
        Some(root) => {
            let installed = preimage.installed_root_set.as_ref().ok_or("no K′")?;
            assert_eq!(installed.members, vec![array::<33>(root)?]);
            assert_eq!(installed.threshold, 1);
        }
    }
    let keys: Vec<([u8; 33], KeyCondition)> = preimage
        .key_state
        .iter()
        .flat_map(|snapshot| &snapshot.keys)
        .map(|entry| (entry.key, entry.condition))
        .collect();
    let expected: Vec<([u8; 33], KeyCondition)> = layout
        .keys
        .iter()
        .map(|(key, condition)| Ok((array::<33>(key)?, *condition)))
        .collect::<Result<_, Error>>()?;
    assert_eq!(keys, expected);
    assert!(preimage.seals.is_empty());
    let Some(Continuation::FixesCommitment(commitment)) = &preimage.continuation else {
        return Err("each vector fixes a commitment".into());
    };
    let commitments: Vec<[u8; 32]> = commitment
        .commitments
        .iter()
        .map(|entry| entry.commitment)
        .collect();
    assert_eq!(commitments, vec![array::<32>(layout.next_commitment)?]);
    assert_eq!(commitment.next_threshold, 1);
    Ok(())
}

#[test]
fn vector_53_round_trips_with_its_printed_values() -> TestResult {
    assert_layout(
        V53_PREIMAGE,
        V53_DIGEST,
        V53_SIGNATURE_FIELD,
        &Layout {
            kind: EventKind::CommitmentRollover,
            standing_root: None,
            roles: &[SignerGroupRole::Reveal, SignerGroupRole::StandingRoot],
            root: None,
            keys: &[],
            next_commitment: V53_NEXT_COMMITMENT,
        },
    )
}

#[test]
fn vector_54_round_trips_with_its_printed_values() -> TestResult {
    assert_layout(
        V54_PREIMAGE,
        V54_DIGEST,
        V54_SIGNATURE_FIELD,
        &Layout {
            kind: EventKind::RootRecovery,
            standing_root: Some(StandingRootDeclaration::CoSigns),
            roles: &[
                SignerGroupRole::Reveal,
                SignerGroupRole::ReplacementRoot,
                SignerGroupRole::StandingRoot,
            ],
            root: Some(V54_ROOT),
            keys: &[
                (V54_ROOT, KeyCondition::Current),
                (V54_ACTIVE, KeyCondition::Current),
                (V41_ROOT, KeyCondition::Superseded),
                (V47B_POINT, KeyCondition::Superseded),
            ],
            next_commitment: V54_NEXT_COMMITMENT,
        },
    )
}

#[test]
fn vector_55_round_trips_with_its_printed_values() -> TestResult {
    assert_layout(
        V55_PREIMAGE,
        V55_DIGEST,
        V55_SIGNATURE_FIELD,
        &Layout {
            kind: EventKind::RootRecovery,
            standing_root: Some(StandingRootDeclaration::Lost),
            roles: &[SignerGroupRole::Reveal, SignerGroupRole::ReplacementRoot],
            root: Some(V55_ROOT),
            keys: &[
                (V55_ROOT, KeyCondition::Current),
                (V55_ACTIVE, KeyCondition::Current),
                (V41_ROOT, KeyCondition::Superseded),
                (V47B_POINT, KeyCondition::Superseded),
            ],
            next_commitment: V55_NEXT_COMMITMENT,
        },
    )
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
    let unit = read_unit(&value)?;
    let consumed = unit.signature_field().map_err(Clone::clone)?.consumed();
    assert_eq!(consumed, first.len());
    let EventUnit::Read(next) = decode_event(&value, consumed) else {
        return Err("the second unit stopped".into());
    };
    assert_eq!(
        next.raw().signed_preimage(),
        bytes(V50_PREIMAGE)?.as_slice()
    );
    assert_eq!(
        next.signature_field().map_err(Clone::clone)?.consumed(),
        second.len()
    );
    assert_step_1_failed(&value, value.len());
    Ok(())
}

/// The seeds `fuzz_kel_decode_event`'s corpus tracks, by file name.
const SEEDS: [&str; 9] = [
    "vector_41",
    "vector_42",
    "vector_50",
    "vector_51_inception",
    "vector_51_key_state",
    "vector_53",
    "vector_54",
    "vector_55",
    "vectors_41_then_50",
];

/// Every unit of every seed of `fuzz_kel_decode_event`'s corpus decodes its
/// body and walks, and the units tile the file, so the fuzz target's
/// re-encode and walk invariants run on each seed.
#[test]
fn every_seed_corpus_unit_decodes_its_body() -> TestResult {
    let corpus =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/fuzz_kel_decode_event");
    for name in SEEDS {
        let value = std::fs::read(corpus.join(name))?;
        let mut offset = 0;
        while offset < value.len() {
            let EventUnit::Read(read) = decode_event(&value, offset) else {
                return Err(format!("{name} stopped at offset {offset}").into());
            };
            read.preimage().map_err(Clone::clone)?;
            offset += read.signature_field().map_err(Clone::clone)?.consumed();
        }
        assert_eq!(offset, value.len(), "{name}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Steps 1 and 2, and the stuffed byte.
// ---------------------------------------------------------------------------

#[test]
fn a_prefix_running_past_value_fails_step_1() -> TestResult {
    let unit = v41_unit()?;
    // Three bytes hold no 4-byte prefix.
    assert_step_1_failed(&unit[..3], 0);
    // The prefix declares one byte more than `value` holds after it.
    let preimage_len = bytes(V41_PREIMAGE)?.len();
    assert_step_1_failed(&unit[..PREFIX + preimage_len - 1], 0);
    // A prefix of u32::MAX.
    let mut huge = unit.clone();
    set_be32(&mut huge, 0, u32::MAX)?;
    assert_step_1_failed(&huge, 0);
    // An offset past `value`, and one at usize::MAX.
    assert_step_1_failed(&unit, unit.len() + 1);
    assert_step_1_failed(&unit, usize::MAX);
    Ok(())
}

/// Vector 41's unit followed by one stuffed byte: `consumed` is Vector 41's
/// unit alone, and the stuffed byte, read as the next unit, fails step 1.
#[test]
fn a_stuffed_byte_is_not_consumed_and_fails_as_the_next_unit() -> TestResult {
    let unit = v41_unit()?;
    let mut value = unit.clone();
    value.push(0x00);
    let read = read_unit(&value)?;
    assert_eq!(
        read.signature_field().map_err(Clone::clone)?.consumed(),
        unit.len()
    );
    assert_step_1_failed(&value, unit.len());
    Ok(())
}

#[test]
fn a_flipped_separator_byte_fails_step_2() -> TestResult {
    for at in [PREFIX, PREFIX + SEPARATOR_LEN - 1] {
        let mut unit = v41_unit()?;
        let byte = *unit.get(at).ok_or("short unit")?;
        set(&mut unit, at, byte ^ 0x01)?;
        assert_eq!(decode_event(&unit, 0), EventUnit::NoSeparator);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 4: the header.
// ---------------------------------------------------------------------------

#[test]
fn an_unregistered_event_type_fails_the_header() -> TestResult {
    let mut unit = v41_unit()?;
    set(&mut unit, FIELDS + KIND, 0x05)?;
    assert_header_failed(
        &unit,
        &HeaderError::UnknownDiscriminator {
            field: HeaderDiscriminator::EventType,
            value: 0x05,
        },
    )
}

#[test]
fn an_unregistered_standing_root_fails_the_header() -> TestResult {
    let mut unit = v41_unit()?;
    set(&mut unit, FIELDS + STANDING_ROOT, 0x03)?;
    assert_header_failed(
        &unit,
        &HeaderError::UnknownDiscriminator {
            field: HeaderDiscriminator::StandingRoot,
            value: 0x03,
        },
    )
}

#[test]
fn a_root_recovery_without_standing_root_fails_the_header() -> TestResult {
    let mut unit = event_unit(V54_PREIMAGE, V54_SIGNATURE_FIELD)?;
    set(&mut unit, FIELDS + STANDING_ROOT, 0x00)?;
    assert_header_failed(&unit, &HeaderError::RootRecoveryWithoutStandingRoot)
}

#[test]
fn an_unregistered_form_fails_the_header() -> TestResult {
    let mut unit = v41_unit()?;
    set(&mut unit, FIELDS + V41_FORM, 0x03)?;
    assert_header_failed(
        &unit,
        &HeaderError::UnknownDiscriminator {
            field: HeaderDiscriminator::SignatureForm,
            value: 0x03,
        },
    )
}

/// A preimage cut inside field 3 fails the header naming the field.
#[test]
fn a_preimage_ending_inside_the_header_fails_it() -> TestResult {
    let preimage = bytes(V41_PREIMAGE)?;
    let unit = unit_of(&preimage[..SEPARATOR_LEN + SEQUENCE + 2], &[])?;
    assert_header_failed(
        &unit,
        &HeaderError::Truncated {
            field: HeaderField::Sequence,
        },
    )
}

/// Vector 53's reveal group names 17 indices, over `MAX_NEXT_SET_SIZE`.
#[test]
fn a_reveal_index_list_over_its_cap_fails_the_header() -> TestResult {
    let mut unit = event_unit(V53_PREIMAGE, V53_SIGNATURE_FIELD)?;
    set_be32(&mut unit, FIELDS + FIRST_INDEX_COUNT, 17)?;
    assert_header_failed(
        &unit,
        &HeaderError::CountOverMax {
            list: SignerList::Indices(SignerGroupRole::Reveal),
            count: 17,
            max: 16,
        },
    )
}

/// Vector 41's form list emptied, then given a second form: at chain
/// position zero the form-list check fails the header as it does at every
/// later position.
#[test]
fn a_form_list_whose_length_differs_from_its_index_list_fails_the_header() -> TestResult {
    for forms in [&[][..], &[0x01, 0x01][..]] {
        let field_bytes = splice_list(&fields(V41_PREIMAGE)?, ONE_GROUP_FORM_COUNT, 1, 1, forms)?;
        assert_header_failed(
            &unit_of_fields(&field_bytes, &bytes(V41_SIGNATURE)?)?,
            &HeaderError::FormListLength(FormListLength {
                role: SignerGroupRole::Root,
                indices: 1,
                forms: forms.len(),
            }),
        )?;
    }
    Ok(())
}

/// A defect in fields 8 to 12 leaves the header and the walk standing: the
/// stages stay apart, so the verifier sees which check failed.
#[test]
fn a_body_defect_leaves_the_header_and_the_walk() -> TestResult {
    let mut unit = v41_unit()?;
    set(&mut unit, FIELDS + V41_ENTRY_0_ROLE, 0x09)?;
    let read = read_unit(&unit)?;
    assert!(matches!(
        read.preimage(),
        Err(BodyError::UnknownDidDiscriminator { .. })
    ));
    assert_eq!(
        read.signature_field().map_err(Clone::clone)?.consumed(),
        unit.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Steps 4 and 5 over every group and position of Vector 54's layout.
// ---------------------------------------------------------------------------

/// Vector 54's three groups, each naming two signers in the raw form.
const V54_ROLES: [SignerGroupRole; 3] = [
    SignerGroupRole::Reveal,
    SignerGroupRole::ReplacementRoot,
    SignerGroupRole::StandingRoot,
];
/// Each group's two indices, distinct across the event.
const V54_INDICES: [[u8; 2]; 3] = [[1, 4], [2, 5], [3, 6]];
/// Where each group's form count sits in the two-signer layout's field
/// bytes: field 6 holds three lists of 4 + 2 bytes from offset 74.
const V54_FORM_COUNTS: [usize; 3] = [92, 98, 104];

/// The field bytes of Vector 54 with each group naming its two indices.
fn v54_two_signer_fields() -> Result<Vec<u8>, Error> {
    let mut preimage = decode_preimage(&fields(V54_PREIMAGE)?)?.into_preimage();
    for (group, indices) in preimage.signer_groups.iter_mut().zip(V54_INDICES) {
        *group = SignerGroup {
            indices: indices.to_vec(),
            forms: vec![SignatureForm::Raw; 2],
        };
    }
    let field_bytes = encode_preimage(&preimage)?.fields().to_vec();
    for at in V54_FORM_COUNTS {
        assert_eq!(field_bytes.get(at..at + 6), Some(&[0, 0, 0, 2, 1, 1][..]));
    }
    Ok(field_bytes)
}

/// Six distinct 64-byte raw signatures, one per named signer in walk order.
fn six_signatures() -> Vec<u8> {
    (0u8..6).flat_map(|signer| [signer + 0x10; 64]).collect()
}

/// The walk fails at whichever group and position the signature field runs
/// out, naming that group's role, the position and the index there.
#[test]
fn the_walk_names_the_role_position_and_index_where_it_fails() -> TestResult {
    let field_bytes = v54_two_signer_fields()?;
    let signatures = six_signatures();
    let whole = read_unit(&unit_of_fields(&field_bytes, &signatures)?)?;
    assert_eq!(whole.walked_groups().map_err(Clone::clone)?.len(), 3);
    for (group, (role, indices)) in V54_ROLES.iter().zip(V54_INDICES).enumerate() {
        for (position, index) in indices.into_iter().enumerate() {
            let walked = 2 * group + position;
            let cut = &signatures[..RAW_CEILING * walked + 63];
            assert_walk_failed(
                &unit_of_fields(&field_bytes, cut)?,
                &walk_error(
                    *role,
                    position,
                    index,
                    IndexedSignatureReadError::Truncated {
                        part: IndexedSignaturePart::RawSignature,
                        remaining: 63,
                    },
                ),
            )?;
        }
    }
    Ok(())
}

/// Each group's form list emptied, cut to one form, and given a third
/// form fails the header naming that group, before any walk.
#[test]
fn the_form_list_check_names_each_group() -> TestResult {
    let field_bytes = v54_two_signer_fields()?;
    for (role, at) in V54_ROLES.iter().zip(V54_FORM_COUNTS) {
        for forms in [&[][..], &[0x01][..], &[0x01, 0x01, 0x01][..]] {
            let mismatched = splice_list(&field_bytes, at, 2, 1, forms)?;
            assert_header_failed(
                &unit_of_fields(&mismatched, &six_signatures())?,
                &HeaderError::FormListLength(FormListLength {
                    role: *role,
                    indices: 2,
                    forms: forms.len(),
                }),
            )?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 5: the signature-field walk in each form.
// ---------------------------------------------------------------------------

#[test]
fn a_raw_signature_cut_short_fails_the_walk() -> TestResult {
    let unit = v41_unit()?;
    assert_walk_failed(
        &unit[..unit.len() - 1],
        &walk_error(
            SignerGroupRole::Root,
            0,
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
    assert_walk_failed(
        &unit[..unit.len() - 64],
        &walk_error(
            SignerGroupRole::StandingRoot,
            0,
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
    assert_walk_failed(&unit, &walk_error(SignerGroupRole::Root, 0, 0, error))
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
        &unit[..layout.field + 4 + 100],
        &walk_error(
            SignerGroupRole::Root,
            0,
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
        &unit[..unit.len() - 1],
        &walk_error(
            SignerGroupRole::Root,
            0,
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
        assert_walk_failed(
            &unit_of(&encoded.signed_preimage(), &[])?,
            &walk_error(
                SignerGroupRole::Root,
                0,
                0,
                IndexedSignatureReadError::Truncated { part, remaining: 0 },
            ),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The received preimage: its identifier and the inception zero checks.
// ---------------------------------------------------------------------------

#[test]
fn the_raw_identifier_reproduces_vectors_41_and_42() -> TestResult {
    assert_eq!(
        read_unit(&v41_unit()?)?.raw().identifier(),
        identifier(V41_IDENTIFIER)?
    );
    assert_eq!(
        read_unit(&v42_unit()?)?.raw().identifier(),
        identifier(V42_IDENTIFIER)?
    );
    Ok(())
}

/// Vector 41's preimage with one byte appended inside its prefix: the body
/// fails to decode, and the identifier is still the hash of the bytes
/// received, as is the digest.
#[test]
fn the_raw_identifier_exists_for_an_inception_whose_body_fails() -> TestResult {
    let mut raw = bytes(V41_PREIMAGE)?;
    raw.push(0x00);
    let read = read_unit(&unit_of(&raw, &bytes(V41_SIGNATURE)?)?)?;
    assert_eq!(read.preimage(), Err(&BodyError::TrailingBytes { count: 1 }));
    assert_eq!(read.raw().signed_preimage(), raw.as_slice());
    assert_eq!(
        read.raw().identifier().as_bytes(),
        &expected_raw_identifier(&raw)
    );
    assert_ne!(read.raw().identifier(), identifier(V41_IDENTIFIER)?);
    let digest: [u8; 32] = Sha256::digest(&raw).into();
    assert_eq!(read.raw().event_digest(), digest);
    Ok(())
}

/// R3's inception zero checks on the received preimage of `unit`.
fn zero_checks(unit: &[u8]) -> Result<Result<(), InceptionHeaderDefect>, Error> {
    Ok(decode_event(unit, 0)
        .raw()
        .ok_or("the unit has no received preimage")?
        .inception_zero_checks())
}

#[test]
fn the_inception_zero_checks_pass_vectors_41_42_and_51() -> TestResult {
    for unit in [
        v41_unit()?,
        v42_unit()?,
        event_unit(V51_INCEPTION_PREIMAGE, V51_INCEPTION_SIGNATURE)?,
    ] {
        zero_checks(&unit)??;
    }
    Ok(())
}

/// Each of the 72 bytes of fields 2, 3 and 4 made nonzero alone names its
/// field.
#[test]
fn the_inception_zero_checks_cover_every_header_byte() -> TestResult {
    for at in IDENTIFIER..STANDING_ROOT {
        let defect = match at {
            IDENTIFIER..SEQUENCE => InceptionHeaderDefect::NonzeroIdentifier,
            SEQUENCE..PREDECESSOR => InceptionHeaderDefect::NonzeroSequence,
            _ => InceptionHeaderDefect::NonzeroPredecessor,
        };
        let mut unit = v41_unit()?;
        set(&mut unit, FIELDS + at, 0x01)?;
        assert_eq!(zero_checks(&unit)?, Err(defect), "byte {at}");
    }
    Ok(())
}

/// Two fields made nonzero name the first in field order, and a kind that
/// is not `Inception` is named before any zero field.
#[test]
fn the_inception_zero_checks_name_the_first_field_in_order() -> TestResult {
    let rows = [
        (
            &[IDENTIFIER + 31, SEQUENCE][..],
            InceptionHeaderDefect::NonzeroIdentifier,
        ),
        (
            &[SEQUENCE + 7, PREDECESSOR][..],
            InceptionHeaderDefect::NonzeroSequence,
        ),
        (
            &[IDENTIFIER, PREDECESSOR + 31][..],
            InceptionHeaderDefect::NonzeroIdentifier,
        ),
    ];
    for (bytes_at, defect) in rows {
        let mut unit = v41_unit()?;
        for at in bytes_at {
            set(&mut unit, FIELDS + at, 0x01)?;
        }
        assert_eq!(zero_checks(&unit)?, Err(defect));
    }
    let mut unit = v41_unit()?;
    set(&mut unit, FIELDS + KIND, 0x02)?;
    set(&mut unit, FIELDS + IDENTIFIER, 0x01)?;
    assert_eq!(
        zero_checks(&unit)?,
        Err(InceptionHeaderDefect::NotInception { value: 0x02 })
    );
    assert_eq!(
        zero_checks(&event_unit(V50_PREIMAGE, V50_SIGNATURE)?)?,
        Err(InceptionHeaderDefect::NotInception { value: 0x02 })
    );
    Ok(())
}

/// A received preimage that ends inside fields 1 to 4 names the field, and
/// one that ends right after field 4 passes: the checks read no later field.
#[test]
fn the_inception_zero_checks_read_only_fields_1_to_4() -> TestResult {
    let preimage = bytes(V41_PREIMAGE)?;
    for (len, field) in [
        (KIND, HeaderField::EventType),
        (IDENTIFIER + 10, HeaderField::Identifier),
        (SEQUENCE + 2, HeaderField::Sequence),
        (STANDING_ROOT - 1, HeaderField::PredecessorDigest),
    ] {
        let unit = unit_of(&preimage[..SEPARATOR_LEN + len], &[])?;
        assert_eq!(
            zero_checks(&unit)?,
            Err(InceptionHeaderDefect::Truncated { field })
        );
    }
    zero_checks(&unit_of(&preimage[..SEPARATOR_LEN + STANDING_ROOT], &[])?)??;
    Ok(())
}

// ---------------------------------------------------------------------------
// MAX_EVENT_BYTES: the encoded length on the encoder and at step 4.
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

fn one_index(form: SignatureForm) -> SignerGroup {
    SignerGroup {
        indices: vec![0],
        forms: vec![form],
    }
}

/// Accepted at exactly `MAX_EVENT_BYTES` and rejected at one byte more, for
/// each form's ceiling, with the exact encoded length.
#[test]
fn the_encoder_bounds_the_encoded_length() -> TestResult {
    let max = max_event_bytes()?;
    for (form, ceiling) in [
        (SignatureForm::Raw, RAW_CEILING),
        (SignatureForm::WebAuthnAssertion, ASSERTION_CEILING),
    ] {
        let at_max = sized_key_state(max, one_index(form), ceiling)?;
        let encoded = encode_preimage(&at_max)?;
        assert_eq!(encoded.signed_preimage().len() + ceiling, max);
        let over = sized_key_state(max + 1, one_index(form), ceiling)?;
        assert_eq!(
            encode_preimage(&over),
            Err(EncodeError::EventTooLong {
                encoded_len: len64(max + 1)?
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
    let mut field_bytes = encode_preimage(preimage)?.fields().to_vec();
    let seals = preimage.seals.len();
    let count_at = field_bytes.len() - 4 - 32 * seals - 4;
    let count = field_bytes
        .get(count_at..count_at + 4)
        .ok_or("short fields")?;
    assert_eq!(count, u32::try_from(seals)?.to_be_bytes());
    set_be32(&mut field_bytes, count_at, u32::try_from(seals + 1)?)?;
    let end = field_bytes.len() - 4;
    field_bytes.splice(end..end, [5; 32]);
    Ok(field_bytes)
}

/// At exactly `MAX_EVENT_BYTES` every stage decodes; one byte over, step 4
/// fails with the exact encoded length and no walk or body runs.
#[test]
fn step_4_bounds_the_encoded_length() -> TestResult {
    let max = max_event_bytes()?;
    for (form, ceiling) in [
        (SignatureForm::Raw, RAW_CEILING),
        (SignatureForm::WebAuthnAssertion, ASSERTION_CEILING),
    ] {
        let at_max = sized_key_state(max, one_index(form), ceiling)?;
        let encoded = encode_preimage(&at_max)?;
        assert_eq!(decode_preimage(encoded.fields())?.preimage(), &at_max);
        let unit = unit_of(&encoded.signed_preimage(), &[0; 64])?;
        let read = read_unit(&unit)?;
        assert_eq!(read.header().encoded_len(), len64(max)?);
        assert_eq!(read.preimage(), Ok(&at_max));
        if form == SignatureForm::Raw {
            assert_eq!(
                read.signature_field().map_err(Clone::clone)?.consumed(),
                unit.len()
            );
        }

        // One byte over: 31 bytes under, plus one 32-byte seal.
        let under = sized_key_state(max - 31, one_index(form), ceiling)?;
        let field_bytes = with_one_more_seal(&under)?;
        let over = HeaderError::EventTooLong {
            encoded_len: len64(max + 1)?,
        };
        assert_eq!(
            decode_preimage(&field_bytes),
            Err(DecodeError::Header(over.clone()))
        );
        assert_header_failed(&unit_of_fields(&field_bytes, &[0; 64])?, &over)?;
    }
    Ok(())
}

/// A group naming 79 assertion-form indices reserves 79 × 840 bytes, past
/// `MAX_EVENT_BYTES` on its own: step 4 fails before the walk, so no unit
/// names more signatures to verify than one legal-size event carries.
#[test]
fn a_unit_naming_more_signatures_than_a_legal_event_carries_is_not_walked() -> TestResult {
    let mut field_bytes = fields(V50_PREIMAGE)?;
    // The form list first, so the index list's offset still holds.
    field_bytes = splice_list(&field_bytes, ONE_GROUP_FORM_COUNT, 1, 1, &[0x02; 79])?;
    field_bytes = splice_list(&field_bytes, FIRST_INDEX_COUNT, 1, 1, &[0; 79])?;
    let encoded_len = SEPARATOR_LEN + field_bytes.len() + 79 * ASSERTION_CEILING;
    assert!(encoded_len > max_event_bytes()?);
    assert_header_failed(
        &unit_of_fields(&field_bytes, &[])?,
        &HeaderError::EventTooLong {
            encoded_len: len64(encoded_len)?,
        },
    )?;
    // The same group cut to fit is walked, and fails at its first signature.
    let mut preimage = v50_key_state()?;
    *preimage.signer_groups.first_mut().ok_or("no group")? = SignerGroup {
        indices: vec![0; 77],
        forms: vec![SignatureForm::WebAuthnAssertion; 77],
    };
    let encoded = encode_preimage(&preimage)?;
    assert_walk_failed(
        &unit_of(&encoded.signed_preimage(), &[])?,
        &walk_error(
            SignerGroupRole::Root,
            0,
            0,
            IndexedSignatureReadError::Truncated {
                part: IndexedSignaturePart::AuthenticatorDataLength,
                remaining: 0,
            },
        ),
    )?;
    Ok(())
}
