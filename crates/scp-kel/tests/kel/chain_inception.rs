//! Position zero (`09-security-model.md` §9.7.4.2 R2, R3): an inception
//! that recomputes to the served identifier and fails R2 or an R3 indicator
//! makes the identifier `InceptionInvalid`, and `validate_inception` refuses
//! the same candidate with the same defect. A unit that fails before it
//! binds is discarded and leaves position zero open.

use scp_did::{CustodyType, Identifier, KeyCondition, KeyRole};
use scp_kel::{
    BodyError, BodyList, CheckStep, ContentDefect, Continuation, DidDiscriminatorField,
    DistinctList, EntryOutcome, EntryValidation, EventPreimage, FailureClass, HeaderDiscriminator,
    HeaderError, InceptionDefect, InceptionHeaderDefect, InceptionRefusal, InstalledRootSet,
    SignerGroupRole, StandingRootDeclaration, ThresholdField, decode_preimage, validate_entry,
    validate_inception,
};

use super::chain_support::{
    ENTRY_ALGORITHM, ENTRY_CONDITION, ENTRY_CUSTODY, ENTRY_ROLE, Error, KIND_AT, NOT_A_POINT, Ring,
    SEPARATOR, STANDING_ROOT_AT, SentinelCase, UNKNOWN_BYTE, Wire, current, entry, entry_at,
    f3_inception, fixes, flip, group, identifier_of, inception, point, root_member,
    service_role_at, sign_inception, sign_inception_wire, signature_field_at, signed_of, v41,
    v41_digest, v41_next, vector,
};
use super::chain_valid::valid;
use super::fixtures::{
    TestResult, V41_ACTIVE, V41_IDENTIFIER, V41_PREIMAGE, V41_ROOT, V50_PREIMAGE, V50_SIGNATURE,
    array, event_unit, identifier,
};

/// One family of rows.
type Builder = fn(&Ring) -> Result<Vec<Row>, Error>;

/// What an `InceptionInvalid` row carries.
enum Expect {
    ZeroCheck(InceptionHeaderDefect),
    Header(fn(&HeaderError) -> bool),
    Body(fn(&BodyError) -> bool),
    Content(ContentDefect),
}

impl Expect {
    fn matches(&self, defect: &InceptionDefect) -> bool {
        match (self, defect) {
            (Self::ZeroCheck(expected), InceptionDefect::ZeroCheck(found)) => expected == found,
            (Self::Header(check), InceptionDefect::Header(found)) => check(found),
            (Self::Body(check), InceptionDefect::Content(ContentDefect::Body(found))) => {
                check(found)
            }
            (Self::Content(expected), InceptionDefect::Content(found)) => expected == found,
            _ => false,
        }
    }

    const fn stage(&self) -> CheckStep {
        match self {
            Self::ZeroCheck(_) | Self::Header(_) => CheckStep::Header,
            Self::Body(_) | Self::Content(_) => CheckStep::Content,
        }
    }
}

struct Row {
    name: &'static str,
    unit: Vec<u8>,
    expect: Expect,
}

/// Serves the row's unit under the identifier its signed preimage
/// recomputes to, and hands the signed preimage to `validate_inception`.
fn check(row: &Row) -> TestResult {
    let name = row.name;
    let signed = signed_of(&row.unit)?;
    let served = identifier_of(signed);
    let EntryValidation { outcome, discarded } = validate_entry(&served, &[&row.unit]);
    let EntryOutcome::InceptionInvalid { defect } = outcome else {
        return Err(format!("{name}: {outcome:?} with {discarded:?}").into());
    };
    assert!(discarded.is_empty(), "{name}: {discarded:?}");
    assert!(row.expect.matches(&defect), "{name}: {defect:?}");
    match validate_inception(signed) {
        Err(refusal @ InceptionRefusal::Invalid(_)) => {
            assert_eq!(refusal, InceptionRefusal::Invalid(defect), "{name}");
            assert_eq!(refusal.stage(), row.expect.stage(), "{name}");
        }
        other => return Err(format!("{name}: validate_inception gave {other:?}").into()),
    }
    Ok(())
}

fn v41_with(edit: impl FnOnce(&mut EventPreimage)) -> Result<EventPreimage, Error> {
    let mut preimage = vector(V41_PREIMAGE)?;
    edit(&mut preimage);
    Ok(preimage)
}

/// Vector 41 edited by `edit`, signed by the root its field 9 installs.
fn signed_v41(ring: &Ring, edit: impl FnOnce(&mut EventPreimage)) -> Result<Vec<u8>, Error> {
    sign_inception(ring, &v41_with(edit)?)
}

/// Vector 41 with its wire bytes patched after encoding.
fn patched_v41(
    ring: &Ring,
    patch: impl FnOnce(&mut Wire) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    let preimage = vector(V41_PREIMAGE)?;
    let mut wire = Wire::of(&preimage);
    patch(&mut wire)?;
    sign_inception_wire(ring, &preimage, &wire)
}

/// Vector 41 whose snapshot `edit` changes, with field 9 kept equal to the
/// snapshot's root.
fn v41_snapshot_edit(
    ring: &Ring,
    edit: impl FnOnce(&mut scp_kel::KeyStateSnapshot),
) -> Result<Vec<u8>, Error> {
    signed_v41(ring, |p| {
        if let Some(snapshot) = p.key_state.as_mut() {
            edit(snapshot);
        }
    })
}

/// A count-prefixed list of `count` distinct `width`-byte items.
fn list(count: u32, width: usize) -> Result<Vec<u8>, Error> {
    let mut out = count.to_be_bytes().to_vec();
    for item in 0..count {
        let mut bytes = vec![0x05; width];
        let first = bytes.first_mut().ok_or("empty item")?;
        *first = u8::try_from(item)?;
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

const fn row(name: &'static str, unit: Vec<u8>, expect: Expect) -> Row {
    Row { name, unit, expect }
}

/// Rows on the root group's indices and on distinctness in fields 9 and 12.
fn signer_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let reference = array(V41_ROOT)?;
    let mut one_named = f3_inception()?;
    one_named.signer_groups = vec![group(&[0])];
    let Some(Continuation::FixesCommitment(commitment)) = vector(V41_PREIMAGE)?.continuation else {
        return Err("Vector 41 fixes a commitment".into());
    };
    let first = *commitment.commitments.first().ok_or("no commitment")?;
    let with_second = |second| {
        let mut doubled = commitment.clone();
        doubled.commitments.push(second);
        signed_v41(ring, |p| {
            p.continuation = Some(Continuation::FixesCommitment(doubled));
        })
    };
    Ok(vec![
        row(
            "A1",
            sign_inception(ring, &one_named)?,
            Expect::Content(ContentDefect::IndexCountBelowThreshold {
                role: SignerGroupRole::Root,
                named: 1,
                threshold: 2,
            }),
        ),
        row(
            "A2",
            signed_v41(ring, |p| p.signer_groups = vec![group(&[0, 0])])?,
            Expect::Content(ContentDefect::RepeatedIndex {
                role: SignerGroupRole::Root,
                index: 0,
            }),
        ),
        row(
            "A3",
            signed_v41(ring, |p| p.signer_groups = vec![group(&[0, 5])])?,
            Expect::Content(ContentDefect::IndexOutOfRange {
                role: SignerGroupRole::Root,
                index: 5,
            }),
        ),
        row(
            "A4a",
            signed_v41(ring, |p| {
                p.installed_root_set = Some(InstalledRootSet {
                    members: vec![reference, reference],
                    threshold: 1,
                });
            })?,
            Expect::Content(ContentDefect::NotDistinct {
                list: DistinctList::RootSet,
            }),
        ),
        row(
            "A4b",
            with_second(scp_did::CommitmentEntry {
                custody_type: CustodyType::Hsm,
                ..first
            })?,
            Expect::Content(ContentDefect::NotDistinct {
                list: DistinctList::Commitments,
            }),
        ),
        row(
            "A4c",
            with_second(first)?,
            Expect::Content(ContentDefect::NotDistinct {
                list: DistinctList::Commitments,
            }),
        ),
    ])
}

/// Rows on the thresholds and the continuation, fields 9 and 12.
fn threshold_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let reference = array(V41_ROOT)?;
    let next = v41_next()?;
    let k_two = point("pr3-kprime-2");
    Ok(vec![
        row(
            "A9a",
            signed_v41(ring, |p| {
                p.installed_root_set = Some(InstalledRootSet {
                    members: vec![reference],
                    threshold: 2,
                });
            })?,
            Expect::Content(ContentDefect::ThresholdOutOfRange {
                field: ThresholdField::Root,
                threshold: 2,
                size: 1,
            }),
        ),
        row(
            "A9b",
            signed_v41(ring, |p| p.continuation = Some(fixes(&[next], 2)))?,
            Expect::Content(ContentDefect::ThresholdOutOfRange {
                field: ThresholdField::Next,
                threshold: 2,
                size: 1,
            }),
        ),
        row(
            "A20",
            sign_inception(
                ring,
                &inception(
                    &[reference, k_two],
                    2,
                    &[0, 1],
                    array(V41_ACTIVE)?,
                    fixes(&[next], 1),
                )?,
            )?,
            Expect::Content(ContentDefect::NextThresholdBelowRoot {
                next_threshold: 1,
                root_threshold: 2,
            }),
        ),
        row(
            "A28a",
            signed_v41(ring, |p| {
                p.continuation = array(V41_ACTIVE).ok().map(|active| fixes(&[active], 1));
            })?,
            Expect::Content(ContentDefect::InstalledKeyCommitted {
                key: array(V41_ACTIVE)?,
            }),
        ),
        row(
            "A31-abandons",
            signed_v41(ring, |p| p.continuation = Some(Continuation::Abandons))?,
            Expect::Content(ContentDefect::InceptionFixesNoCommitment),
        ),
        row(
            "A31-none",
            signed_v41(ring, |p| p.continuation = None)?,
            Expect::Content(ContentDefect::InceptionFixesNoCommitment),
        ),
    ])
}

/// Criterion 7 at position zero: field 9 differs from the snapshot's root
/// in members, in member order, and in threshold.
fn mismatch_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let reference = array(V41_ROOT)?;
    let k_two = point("pr3-kprime-2");
    let two_roots = inception(
        &[reference, k_two],
        1,
        &[0, 1],
        array(V41_ACTIVE)?,
        fixes(&[v41_next()?], 1),
    )?;
    let mut rows = Vec::new();
    let cases = [
        ("A38-members", vector(V41_PREIMAGE)?, vec![k_two], 1),
        ("A38-order", two_roots.clone(), vec![k_two, reference], 1),
        ("A38-threshold", two_roots, vec![reference, k_two], 2),
    ];
    for (name, mut preimage, members, threshold) in cases {
        preimage.installed_root_set = Some(InstalledRootSet { members, threshold });
        rows.push(row(
            name,
            sign_inception(ring, &preimage)?,
            Expect::Content(ContentDefect::InstalledRootMismatch),
        ));
    }
    Ok(rows)
}

/// Rows on the snapshot's size, witnesses and interval, field 10.
fn snapshot_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let reference = array(V41_ROOT)?;
    let active = array(V41_ACTIVE)?;
    let content = Expect::Content;
    Ok(vec![
        row(
            "A7",
            {
                let mut roots = vec![reference];
                roots.extend((0..16).map(|n| point(&format!("pr3-root-{n:02}"))));
                let mut preimage = inception(&roots, 1, &[0], active, fixes(&[v41_next()?], 1))?;
                preimage.installed_root_set = Some(InstalledRootSet {
                    members: vec![reference],
                    threshold: 1,
                });
                sign_inception(ring, &preimage)?
            },
            content(ContentDefect::RootSetTooLarge { size: 17 }),
        ),
        row(
            "A15",
            v41_snapshot_edit(ring, |s| s.keys.push(current(active, KeyRole::Active)))?,
            content(ContentDefect::KeyListedTwice { key: active }),
        ),
        row(
            "A21",
            v41_snapshot_edit(ring, |s| s.keys = vec![root_member(reference)])?,
            content(ContentDefect::ServiceRoleUnresolved),
        ),
        row(
            "A22a",
            v41_snapshot_edit(ring, |s| s.witnessing_interval = 299)?,
            content(ContentDefect::WitnessIntervalOutOfRange { interval: 299 }),
        ),
        row(
            "A22b",
            v41_snapshot_edit(ring, |s| s.witnessing_interval = 604_801)?,
            content(ContentDefect::WitnessIntervalOutOfRange { interval: 604_801 }),
        ),
        row(
            "A23a",
            v41_snapshot_edit(ring, |s| {
                s.witnesses = (0..33_u8)
                    .map(|n| Identifier::from_bytes([n; 32]))
                    .collect();
            })?,
            Expect::Body(|e| {
                matches!(
                    e,
                    BodyError::CountOverMax {
                        list: BodyList::Witnesses,
                        count: 33,
                        max: 32
                    }
                )
            }),
        ),
        row(
            "A23b",
            v41_snapshot_edit(ring, |s| {
                if let Some(witness) = s.witnesses.first().copied() {
                    s.witnesses.push(witness);
                }
            })?,
            content(ContentDefect::NotDistinct {
                list: DistinctList::Witnesses,
            }),
        ),
    ])
}

/// Rows on the snapshot's key list and roles, field 10.
fn snapshot_key_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let reference = array(V41_ROOT)?;
    let new_active = point("pr3-active-2");
    let content = Expect::Content;
    Ok(vec![
        row(
            "A26",
            v41_snapshot_edit(ring, |s| s.keys.push(current(new_active, KeyRole::Active)))?,
            content(ContentDefect::TwoCurrentInRole {
                role: KeyRole::Active,
            }),
        ),
        row(
            "A29",
            v41_snapshot_edit(ring, |s| s.delegator = Identifier::from_bytes([0x11; 32]))?,
            content(ContentDefect::NonzeroDelegator),
        ),
        row(
            "A39",
            v41_snapshot_edit(ring, |s| {
                s.keys = vec![
                    root_member(reference),
                    current(NOT_A_POINT, KeyRole::Active),
                ];
            })?,
            content(ContentDefect::InvalidPoint { key: NOT_A_POINT }),
        ),
        row(
            "A46",
            v41_snapshot_edit(ring, |s| {
                s.keys
                    .push(entry(new_active, KeyRole::Active, KeyCondition::Superseded));
            })?,
            content(ContentDefect::KeyNotCurrentNorDropped { key: new_active }),
        ),
        row(
            "A47",
            v41_snapshot_edit(ring, |s| s.service_key_role = KeyRole::RootMember)?,
            content(ContentDefect::ServiceRoleNotActive {
                role: KeyRole::RootMember,
            }),
        ),
    ])
}

/// Rows whose key-entry or service-role discriminator no decoder accepts.
fn decode_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let mut rows = Vec::new();
    let body: [(&'static str, usize, DidDiscriminatorField); 4] = [
        ("A17", ENTRY_ALGORITHM, DidDiscriminatorField::KeyAlgorithm),
        ("A19b", ENTRY_CUSTODY, DidDiscriminatorField::CustodyType),
        ("A19c", ENTRY_ROLE, DidDiscriminatorField::Role),
        ("A19d", ENTRY_CONDITION, DidDiscriminatorField::Condition),
    ];
    for (name, at, field) in body {
        let unit = patched_v41(ring, |wire| {
            Wire::set(&mut wire.snapshot, entry_at(1, at), UNKNOWN_BYTE)
        })?;
        let expect = match field {
            DidDiscriminatorField::KeyAlgorithm => Expect::Body(|e| {
                matches!(
                    e,
                    BodyError::UnknownDidDiscriminator {
                        field: DidDiscriminatorField::KeyAlgorithm,
                        ..
                    }
                )
            }),
            DidDiscriminatorField::CustodyType => Expect::Body(|e| {
                matches!(
                    e,
                    BodyError::UnknownDidDiscriminator {
                        field: DidDiscriminatorField::CustodyType,
                        ..
                    }
                )
            }),
            DidDiscriminatorField::Role => Expect::Body(|e| {
                matches!(
                    e,
                    BodyError::UnknownDidDiscriminator {
                        field: DidDiscriminatorField::Role,
                        ..
                    }
                )
            }),
            _ => Expect::Body(|e| {
                matches!(
                    e,
                    BodyError::UnknownDidDiscriminator {
                        field: DidDiscriminatorField::Condition,
                        ..
                    }
                )
            }),
        };
        rows.push(row(name, unit, expect));
    }
    let service = service_role_at(
        vector(V41_PREIMAGE)?
            .key_state
            .as_ref()
            .ok_or("no snapshot")?,
    );
    rows.push(row(
        "A19e",
        patched_v41(ring, |wire| {
            Wire::set(&mut wire.snapshot, service, UNKNOWN_BYTE)
        })?,
        Expect::Body(|e| {
            matches!(
                e,
                BodyError::UnknownDidDiscriminator {
                    field: DidDiscriminatorField::ServiceKeyRole,
                    ..
                }
            )
        }),
    ));
    Ok(rows)
}

/// Rows whose continuation discriminator or list count no decoder accepts.
fn count_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let mut rows = Vec::new();
    rows.push(row(
        "A19f",
        patched_v41(ring, |wire| Wire::set(&mut wire.continuation, 0, 0x02))?,
        Expect::Body(|e| matches!(e, BodyError::UnknownContinuation { value: 0x02 })),
    ));
    rows.push(row(
        "A5",
        patched_v41(ring, |wire| {
            let mut installed = list(17, 33)?;
            installed.extend_from_slice(&1_u32.to_be_bytes());
            wire.installed = installed;
            Ok(())
        })?,
        Expect::Body(|e| {
            matches!(
                e,
                BodyError::CountOverMax {
                    list: BodyList::InstalledRootSet,
                    count: 17,
                    max: 16
                }
            )
        }),
    ));
    rows.push(row(
        "A6a",
        patched_v41(ring, |wire| {
            let mut continuation = vec![0x01];
            continuation.extend(list(17, 34)?);
            continuation.extend_from_slice(&1_u32.to_be_bytes());
            wire.continuation = continuation;
            Ok(())
        })?,
        Expect::Body(|e| {
            matches!(
                e,
                BodyError::CountOverMax {
                    list: BodyList::Commitments,
                    count: 17,
                    max: 16
                }
            )
        }),
    ));
    Ok(rows)
}

/// Rows the header or the zero check refuses.
fn header_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    Ok(vec![
        row(
            "A18a-short",
            patched_v41(ring, |wire| {
                wire.forms = 0_u32.to_be_bytes().to_vec();
                Ok(())
            })?,
            Expect::Header(
                |e| matches!(e, HeaderError::FormListLength(l) if l.indices == 1 && l.forms == 0),
            ),
        ),
        row(
            "A18a-long",
            patched_v41(ring, |wire| {
                wire.forms = vec![0, 0, 0, 2, 1, 1];
                Ok(())
            })?,
            Expect::Header(
                |e| matches!(e, HeaderError::FormListLength(l) if l.indices == 1 && l.forms == 2),
            ),
        ),
        row(
            "A18b",
            patched_v41(ring, |wire| Wire::set(&mut wire.forms, 4, 0x03))?,
            Expect::Header(|e| {
                matches!(
                    e,
                    HeaderError::UnknownDiscriminator {
                        field: HeaderDiscriminator::SignatureForm,
                        value: 0x03
                    }
                )
            }),
        ),
        row(
            "A19a",
            patched_v41(ring, |wire| {
                Wire::set(&mut wire.head, STANDING_ROOT_AT, 0x03)
            })?,
            Expect::Header(|e| {
                matches!(
                    e,
                    HeaderError::UnknownDiscriminator {
                        field: HeaderDiscriminator::StandingRoot,
                        value: 0x03
                    }
                )
            }),
        ),
        row(
            "A19",
            patched_v41(ring, |wire| Wire::set(&mut wire.head, KIND_AT, 0x05))?,
            Expect::ZeroCheck(InceptionHeaderDefect::NotInception { value: 0x05 }),
        ),
        row(
            "A41a",
            signed_v41(ring, |p| p.identifier = Identifier::from_bytes([0x01; 32]))?,
            Expect::ZeroCheck(InceptionHeaderDefect::NonzeroIdentifier),
        ),
        row(
            "A41b",
            signed_v41(ring, |p| p.sequence = 1)?,
            Expect::ZeroCheck(InceptionHeaderDefect::NonzeroSequence),
        ),
        row(
            "A41c",
            signed_v41(ring, |p| p.predecessor_digest = [0x01; 32])?,
            Expect::ZeroCheck(InceptionHeaderDefect::NonzeroPredecessor),
        ),
        row(
            "A41d",
            event_unit(V50_PREIMAGE, V50_SIGNATURE)?,
            Expect::ZeroCheck(InceptionHeaderDefect::NotInception { value: 0x02 }),
        ),
        row(
            "A8",
            signed_v41(ring, |p| {
                p.seals = (0..2048_u32)
                    .map(|n| {
                        let mut seal = [0x33; 32];
                        seal[..4].copy_from_slice(&n.to_be_bytes());
                        seal
                    })
                    .collect();
            })?,
            Expect::Header(|e| matches!(e, HeaderError::EventTooLong { .. })),
        ),
    ])
}

/// Rows holding a field an inception carries as its sentinel.
fn sentinel_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let mut rows = Vec::new();
    let sentinels: [SentinelCase; 3] = [
        ("A48-Inception-5", 5, |p| {
            p.standing_root = Some(StandingRootDeclaration::CoSigns);
        }),
        ("A48-Inception-8", 8, |p| p.revealed_keys = vec![[0x02; 33]]),
        ("A48-Inception-11", 11, |p| p.seals = vec![[0x22; 32]]),
    ];
    for (name, field, edit) in sentinels {
        rows.push(row(
            name,
            signed_v41(ring, edit)?,
            Expect::Content(ContentDefect::SentinelHeld { field }),
        ));
    }
    Ok(rows)
}

#[test]
fn every_inception_defect_makes_the_identifier_invalid() -> TestResult {
    let ring = Ring::new()?;
    let builders: [Builder; 9] = [
        signer_rows,
        sentinel_rows,
        threshold_rows,
        mismatch_rows,
        snapshot_rows,
        snapshot_key_rows,
        decode_rows,
        count_rows,
        header_rows,
    ];
    for build in builders {
        for row in build(&ring)? {
            check(&row)?;
        }
    }
    Ok(())
}

/// A41d: a later event's bytes served at position zero derive no
/// identifier through `inception_identifier`, and R3 reads its field 1.
#[test]
fn a_later_event_derives_no_inception_identifier() -> TestResult {
    let unit = event_unit(V50_PREIMAGE, V50_SIGNATURE)?;
    let fields = signed_of(&unit)?
        .strip_prefix(SEPARATOR)
        .ok_or("no separator")?;
    let decoded = decode_preimage(fields)?;
    assert_eq!(decoded.inception_identifier(), None);
    Ok(())
}

/// Every unit served for position zero is discarded: the verdict is
/// `NoInception` with each discard.
fn no_inception(units: &[&[u8]]) -> Result<Vec<scp_kel::Discarded>, Error> {
    let EntryValidation { outcome, discarded } =
        validate_entry(&identifier(V41_IDENTIFIER)?, units);
    if outcome == EntryOutcome::NoInception {
        Ok(discarded)
    } else {
        Err(format!("expected NoInception, got {outcome:?}").into())
    }
}

fn v41_unit() -> Result<Vec<u8>, Error> {
    Ok(v41()?.units.first().ok_or("no V41 unit")?.clone())
}

/// What one discard of the first served unit carries.
struct Single {
    stage: CheckStep,
    class: FailureClass,
    /// The position the unit was read for; `None` where it joined no chain.
    read_for: Option<u64>,
    digest: Option<[u8; 32]>,
}

/// One discard, of the first served unit.
fn assert_single(discarded: &[scp_kel::Discarded], expected: &Single) -> TestResult {
    let [discard] = discarded else {
        return Err(format!("discards {discarded:?}").into());
    };
    assert_eq!(discard.served_index(), 0, "{discard:?}");
    assert_eq!(discard.read_for(), expected.read_for, "{discard:?}");
    assert_eq!(discard.stage(), expected.stage, "{discard:?}");
    assert_eq!(discard.class(), expected.class, "{discard:?}");
    assert_eq!(discard.digest(), expected.digest, "{discard:?}");
    Ok(())
}

/// C1: a flipped preimage byte recomputes to another identifier.
#[test]
fn an_inception_that_recomputes_elsewhere_is_discarded() -> TestResult {
    let unit = v41_unit()?;
    let last = signature_field_at(&unit)? - 1;
    let flipped = flip(&unit, last)?;
    assert_single(
        &no_inception(&[&flipped])?,
        &Single {
            stage: CheckStep::InceptionBinding,
            class: FailureClass::ProvesNothing,
            read_for: Some(0),
            digest: None,
        },
    )
}

/// C3 at position zero: a flipped signature byte fails 7b, with Vector
/// 41's digest.
#[test]
fn an_inception_whose_signature_fails_is_discarded_with_its_digest() -> TestResult {
    let unit = v41_unit()?;
    let flipped = flip(&unit, signature_field_at(&unit)? + 10)?;
    assert_single(
        &no_inception(&[&flipped])?,
        &Single {
            stage: CheckStep::VerifiedCount,
            class: FailureClass::CopyDamage,
            read_for: Some(0),
            digest: Some(v41_digest()?),
        },
    )
}

/// C5: a one-byte unit after a valid inception is discarded at step 1;
/// C5b: one byte appended inside the inception's unit is discarded at the
/// walk.
#[test]
fn bytes_no_unit_frames_are_discarded() -> TestResult {
    let unit = v41_unit()?;
    let (chain, discarded) = valid(&identifier(V41_IDENTIFIER)?, &[&unit, &[0x00]])?;
    assert_eq!(chain.head_digest(), v41_digest()?);
    let [discard] = discarded.as_slice() else {
        return Err(format!("discards {discarded:?}").into());
    };
    assert_eq!(
        (
            discard.served_index(),
            discard.read_for(),
            discard.stage(),
            discard.class(),
            discard.digest()
        ),
        (1, None, CheckStep::Unit, FailureClass::ProvesNothing, None)
    );

    let mut appended = unit;
    appended.push(0x00);
    assert_single(
        &no_inception(&[&appended])?,
        &Single {
            stage: CheckStep::Walk,
            class: FailureClass::CopyDamage,
            read_for: Some(0),
            digest: None,
        },
    )
}

/// C10: a flipped separator byte; C12: a length prefix past the unit.
#[test]
fn unframed_and_unseparated_inceptions_are_discarded() -> TestResult {
    let unit = v41_unit()?;
    let unseparated = flip(&unit, 4)?;
    assert_single(
        &no_inception(&[&unseparated])?,
        &Single {
            stage: CheckStep::Separator,
            class: FailureClass::Illegal,
            read_for: None,
            digest: None,
        },
    )?;
    match validate_inception(signed_of(&unseparated)?) {
        Err(InceptionRefusal::Discarded(discard)) => {
            assert_eq!(discard.stage(), CheckStep::Separator);
        }
        other => return Err(format!("C10: {other:?}").into()),
    }

    let mut unframed = unit;
    let prefix = unframed.first_chunk_mut::<4>().ok_or("no prefix")?;
    *prefix = (u32::from_be_bytes(*prefix) + 1000).to_be_bytes();
    assert_single(
        &no_inception(&[&unframed])?,
        &Single {
            stage: CheckStep::Unit,
            class: FailureClass::ProvesNothing,
            read_for: None,
            digest: None,
        },
    )
}

/// R2 accepts Vector 41 unsigned, and the signature field of 64 zero bytes
/// is no part of the candidate.
#[test]
fn vector_41_passes_validate_inception() -> TestResult {
    let unit = v41_unit()?;
    let change = validate_inception(signed_of(&unit)?).map_err(|refusal| format!("{refusal:?}"))?;
    assert_eq!(change.preimage(), signed_of(&unit)?);
    Ok(())
}

/// Vector 41 with `extra` more commitments and `seals` key-event seals, as
/// an unsigned-check unit signed by its root.
fn v41_padded(ring: &Ring, extra: usize, seals: usize) -> Result<Vec<u8>, Error> {
    signed_v41(ring, |p| {
        if let Some(Continuation::FixesCommitment(commitment)) = p.continuation.as_mut() {
            for n in 0..extra {
                let mut entry = scp_did::CommitmentEntry {
                    commitment: [0x40; 32],
                    custody_type: CustodyType::Passkey,
                    key_algorithm: scp_did::KeyAlgorithm::EcdsaP256Sha256,
                };
                entry.commitment[..8].copy_from_slice(&(n as u64).to_be_bytes());
                commitment.commitments.push(entry);
            }
        }
        p.seals = (0..seals)
            .map(|n| {
                let mut seal = [0x33; 32];
                seal[..8].copy_from_slice(&(n as u64).to_be_bytes());
                seal
            })
            .collect();
    })
}

/// Criterion 8 at position zero: an inception whose encoded length, its
/// signed preimage plus the one raw root signature, is exactly
/// `MAX_EVENT_BYTES` passes step 4's length check, and one seal more fails
/// it with the encoded length. An inception carries field 11 as its
/// sentinel, so seals are the one list that fills it to the bound, and the
/// unit at the bound fails step 3's second half at that sentinel instead.
#[test]
fn an_inception_at_max_event_bytes_passes_the_length_check() -> TestResult {
    let ring = Ring::new()?;
    // Commitments are 34 bytes and seals 32, so some count of extra
    // commitments leaves room for a whole number of seals.
    let mut found = None;
    for extra in 0..15 {
        let empty = v41_padded(&ring, extra, 0)?;
        let encoded = signed_of(&empty)?.len() + 64;
        let room = 65_536 - encoded;
        if room.is_multiple_of(32) {
            found = Some((extra, room / 32));
            break;
        }
    }
    let (extra, seals) = found.ok_or("no commitment count aligns the seals")?;
    let at_bound = v41_padded(&ring, extra, seals)?;
    assert_eq!(signed_of(&at_bound)?.len() + 64, 65_536);
    let over = v41_padded(&ring, extra, seals + 1)?;
    for (unit, expected) in [
        (
            at_bound,
            InceptionDefect::Content(ContentDefect::SentinelHeld { field: 11 }),
        ),
        (
            over,
            InceptionDefect::Header(HeaderError::EventTooLong {
                encoded_len: 65_568,
            }),
        ),
    ] {
        let served = identifier_of(signed_of(&unit)?);
        let EntryValidation { outcome, discarded } = validate_entry(&served, &[&unit]);
        assert!(discarded.is_empty(), "{discarded:?}");
        assert_eq!(
            outcome,
            EntryOutcome::InceptionInvalid {
                defect: expected.clone()
            }
        );
        assert_eq!(
            validate_inception(signed_of(&unit)?),
            Err(InceptionRefusal::Invalid(expected))
        );
    }
    Ok(())
}
