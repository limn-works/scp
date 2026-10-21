//! One fixture per R3 defect past the inception (`09-security-model.md`
//! §9.7.4.2 R3): each row serves a base chain and one unit, and expects
//! `Valid` at the base's head with one `Discarded` at the next position.
//!
//! Each row also checks that `extend` on the base returns the same
//! `Discarded` with the chain unchanged, and that `validate_change` on the
//! unit's signed preimage fails at the same check where that check reads no
//! signature, and passes or fails later where it does.

use scp_did::{CustodyType, Identifier, KeyCondition, KeyEntry, KeyRole};
use scp_kel::{
    BodyError, BodyList, CheckStep, ContentDefect, Continuation, DidDiscriminatorField,
    DistinctList, EventDefect, EventKind, EventPreimage, HeaderDiscriminator, HeaderError,
    InstalledRootSet, KeyStateSnapshot, SignerGroupRole, SignerList, StandingRootDeclaration,
    StandingRootSigning, ThresholdField, prerotation_commitment,
};

use super::chain_support::{
    Base, ENTRY_ALGORITHM, ENTRY_CONDITION, ENTRY_CUSTODY, ENTRY_ROLE, Error, KIND_AT, NOT_A_POINT,
    Recovery, Ring, STANDING_ROOT_AT, SentinelCase, UNKNOWN_BYTE, Wire, current, digest_of, entry,
    entry_at, f1, f2, f2_inception, f3, f3_inception, fixes, fx, group, key_state_on, point,
    reference, service_role_at, set_snapshot, sign_on, sign_wire, signed, signed_of, tertiary,
    unit, v41, v41_changed, v41_next, v41_v50, v41_v53, v41_v55, v41_v68, v42, v53_with, v54_with,
    v55_with, vector,
};
use super::chain_valid::{chain_of, valid};
use super::fixtures::{
    TestResult, V41_ACTIVE, V41_IDENTIFIER, V41_ROOT, V42_IDENTIFIER, V54_PREIMAGE, array,
    identifier, v41_snapshot,
};

/// What a row's `Discarded` carries.
pub enum Expect {
    Content(ContentDefect),
    Body(fn(&BodyError) -> bool),
    Header(fn(&HeaderError) -> bool),
    NamedCount,
    VerifiedCount,
    Walk,
    Signature(SignerGroupRole, u8),
    Predecessor,
    Separator,
}

impl Expect {
    const fn stage(&self) -> CheckStep {
        match self {
            Self::Content(_) | Self::Body(_) => CheckStep::Content,
            Self::Header(_) | Self::Predecessor => CheckStep::Header,
            Self::NamedCount => CheckStep::NamedCount,
            Self::VerifiedCount => CheckStep::VerifiedCount,
            Self::Walk => CheckStep::Walk,
            Self::Signature(..) => CheckStep::Signatures,
            Self::Separator => CheckStep::Separator,
        }
    }

    fn matches(&self, defect: &EventDefect, digest: [u8; 32]) -> bool {
        match (self, defect) {
            (Self::Content(expected), EventDefect::Content { digest: d, defect }) => {
                *d == digest && defect == expected
            }
            (
                Self::Body(check),
                EventDefect::Content {
                    digest: d,
                    defect: ContentDefect::Body(error),
                },
            ) => *d == digest && check(error),
            (Self::Header(check), EventDefect::Header(error)) => check(error),
            (Self::NamedCount, EventDefect::NamedCountShort { digest: d })
            | (Self::VerifiedCount, EventDefect::VerifiedCountShort { digest: d }) => *d == digest,
            (Self::Walk, EventDefect::Walk(_) | EventDefect::UnconsumedBytes { .. })
            | (Self::Predecessor, EventDefect::PredecessorMismatch { .. })
            | (Self::Separator, EventDefect::NoSeparator) => true,
            (
                Self::Signature(role, index),
                EventDefect::Signature {
                    digest: d,
                    role: r,
                    index: i,
                    ..
                },
            ) => *d == digest && r == role && i == index,
            _ => false,
        }
    }
}

/// A row that writes an unknown byte at an offset and expects a body error.
type BodyCase<At> = (&'static str, At, fn(&BodyError) -> bool);
/// A row that patches the wire and expects a header error.
type HeaderCase = (
    &'static str,
    fn(&mut Wire) -> Result<(), Error>,
    fn(&HeaderError) -> bool,
);

pub struct Row {
    pub name: &'static str,
    pub base: Base,
    pub unit: Vec<u8>,
    pub expect: Expect,
}

const fn rank(step: CheckStep) -> u8 {
    match step {
        CheckStep::Unit => 0,
        CheckStep::Separator => 1,
        CheckStep::InceptionBinding => 2,
        CheckStep::Header => 3,
        CheckStep::Walk => 4,
        CheckStep::NamedCount => 5,
        CheckStep::VerifiedCount => 6,
        CheckStep::Content => 7,
        CheckStep::Signatures => 8,
    }
}

/// Runs one row through `validate_chain`, `extend` and `validate_change`.
pub fn check(row: &Row) -> TestResult {
    let name = row.name;
    let (chain, discarded) = valid(&row.base.identifier, &row.base.with(&row.unit))
        .map_err(|error| format!("{name}: {error}"))?;
    assert_eq!(chain.head_digest(), row.base.head, "{name}");
    let [discard] = discarded.as_slice() else {
        return Err(format!("{name}: discards {discarded:?}").into());
    };
    assert_eq!(discard.at_position(), row.base.len(), "{name}");
    let stage = row.expect.stage();
    assert_eq!(discard.stage(), stage, "{name}: {discard:?}");
    let signed = signed_of(&row.unit)?;
    let digest = digest_of(signed);
    assert!(
        row.expect.matches(discard.defect(), digest),
        "{name}: {discard:?}"
    );
    let carries_digest = matches!(
        stage,
        CheckStep::NamedCount
            | CheckStep::VerifiedCount
            | CheckStep::Content
            | CheckStep::Signatures
    );
    assert_eq!(discard.digest(), carries_digest.then_some(digest), "{name}");

    let base = chain_of(&row.base)?;
    let change = base.validate_change(signed);
    match base.clone().extend(&row.unit) {
        Ok(_) => return Err(format!("{name}: extend accepted the unit").into()),
        Err((back, extended)) => {
            assert_eq!(back, base, "{name}");
            assert_eq!(&extended, discard, "{name}");
        }
    }
    let reads_no_signature = matches!(
        stage,
        CheckStep::Separator | CheckStep::Header | CheckStep::NamedCount | CheckStep::Content
    );
    match change {
        Err(refused) if reads_no_signature => assert_eq!(&refused, discard, "{name}"),
        Ok(_) if reads_no_signature => {
            return Err(format!("{name}: validate_change accepted").into());
        }
        Err(refused) => assert!(rank(refused.stage()) > rank(stage), "{name}: {refused:?}"),
        Ok(_) => {}
    }
    Ok(())
}

/// The V41 snapshot every `KeyState` on Vector 41 edits.
fn v41_keys() -> Result<(KeyEntry, KeyEntry), Error> {
    Ok((
        current(array(V41_ROOT)?, KeyRole::RootMember),
        current(array(V41_ACTIVE)?, KeyRole::Active),
    ))
}

/// A `KeyState` on `base` carrying `snapshot`, edited by `edit`, signed by
/// the root standing at `base`'s head.
fn key_state(
    ring: &Ring,
    base: &Base,
    snapshot: KeyStateSnapshot,
    edit: impl FnOnce(&mut EventPreimage),
) -> Result<Vec<u8>, Error> {
    let mut preimage = key_state_on(base, snapshot);
    edit(&mut preimage);
    sign_on(ring, base, &preimage)
}

/// A `KeyState` on Vector 41 whose snapshot `edit_snapshot` changes from
/// Vector 41's, at interval 7200.
fn v41_key_state(
    ring: &Ring,
    edit_snapshot: impl FnOnce(&mut KeyStateSnapshot) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    let mut changed = v41_changed()?;
    edit_snapshot(&mut changed)?;
    key_state(ring, &v41()?, changed, |_| {})
}

/// A `KeyState` on Vector 41 whose wire bytes `patch` edits.
fn v41_key_state_wire(
    ring: &Ring,
    edit: impl FnOnce(&mut EventPreimage),
    patch: impl FnOnce(&mut Wire) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    let base = v41()?;
    let mut preimage = key_state_on(&base, v41_changed()?);
    edit(&mut preimage);
    let mut wire = Wire::of(&preimage);
    patch(&mut wire)?;
    sign_wire(ring, &base, &preimage, &wire)
}

fn on_v41(ring: &Ring, preimage: &EventPreimage) -> Result<Vec<u8>, Error> {
    sign_on(ring, &v41()?, preimage)
}

fn on_v41_wire(
    ring: &Ring,
    preimage: &EventPreimage,
    patch: impl FnOnce(&mut Wire) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    let mut wire = Wire::of(preimage);
    patch(&mut wire)?;
    sign_wire(ring, &v41()?, preimage, &wire)
}

/// A count-prefixed list of `count` distinct `width`-byte items, none a
/// valid point.
fn list(count: u32, width: usize) -> Vec<u8> {
    let mut out = count.to_be_bytes().to_vec();
    for item in 0..count {
        let mut bytes = vec![0x05; width];
        if let Some(first) = bytes.first_mut() {
            *first = u8::try_from(item).unwrap_or(u8::MAX);
        }
        out.extend_from_slice(&bytes);
    }
    out
}

const fn row(name: &'static str, base: Base, unit: Vec<u8>, expect: Expect) -> Row {
    Row {
        name,
        base,
        unit,
        expect,
    }
}

fn v41_row(name: &'static str, unit: Vec<u8>, expect: Expect) -> Result<Row, Error> {
    Ok(row(name, v41()?, unit, expect))
}

const fn content(defect: ContentDefect) -> Expect {
    Expect::Content(defect)
}

/// The rows on a `KeyState` after Vector 41.
fn key_state_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let (_, active) = v41_keys()?;
    let new_active = point("pr3-active-2");
    let base = v41()?;
    let mut rows = Vec::new();

    let mut one_index = f3_inception()?.key_state.ok_or("F3 carries a snapshot")?;
    one_index.witnessing_interval = 7200;
    let f3 = f3(ring)?;
    let named_one = key_state(ring, &f3, one_index, |preimage| {
        preimage.signer_groups = vec![group(&[0])];
    })?;
    rows.push(row("A1/C9", f3, named_one, Expect::NamedCount));

    rows.push(v41_row(
        "A2",
        key_state(ring, &base, v41_changed()?, |p| {
            p.signer_groups = vec![group(&[0, 0])];
        })?,
        content(ContentDefect::RepeatedIndex {
            role: SignerGroupRole::Root,
            index: 0,
        }),
    )?);
    rows.push(v41_row(
        "A3",
        key_state(ring, &base, v41_changed()?, |p| {
            p.signer_groups = vec![group(&[0, 5])];
        })?,
        content(ContentDefect::IndexOutOfRange {
            role: SignerGroupRole::Root,
            index: 5,
        }),
    )?);
    rows.push(v41_row(
        "A3-keyless",
        key_state(ring, &base, v41_changed()?, |p| {
            p.signer_groups = vec![group(&[5])];
        })?,
        Expect::NamedCount,
    )?);

    rows.push(v41_row(
        "A7",
        v41_key_state(ring, |s| {
            for member in 0..16 {
                s.keys.insert(
                    1,
                    current(point(&format!("pr3-root-{member:02}")), KeyRole::RootMember),
                );
            }
            Ok(())
        })?,
        content(ContentDefect::RootSetTooLarge { size: 17 }),
    )?);
    rows.push(v41_row(
        "A10",
        key_state(ring, &base, v41_changed()?, |p| p.sequence = 2)?,
        content(ContentDefect::SequenceNotNext {
            expected: 1,
            found: 2,
        }),
    )?);
    rows.push(v41_row(
        "A13",
        v41_key_state(ring, |s| {
            s.root_threshold = 2;
            Ok(())
        })?,
        content(ContentDefect::KeyStateRootChanged),
    )?);
    rows.push(v41_row(
        "A15",
        v41_key_state(ring, |s| {
            s.keys.push(active);
            Ok(())
        })?,
        content(ContentDefect::KeyListedTwice { key: active.key }),
    )?);
    rows.push(v41_row(
        "A16",
        v41_key_state(ring, |s| {
            s.keys
                .push(entry(new_active, KeyRole::Active, KeyCondition::Retired));
            Ok(())
        })?,
        content(ContentDefect::KeyNotCurrentNorDropped { key: new_active }),
    )?);

    Ok(rows)
}

fn key_state_discriminator_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let mut rows = Vec::new();
    let patches: [BodyCase<usize>; 4] = [
        ("A17-field-10", ENTRY_ALGORITHM, |e| {
            matches!(
                e,
                BodyError::UnknownDidDiscriminator {
                    field: DidDiscriminatorField::KeyAlgorithm,
                    ..
                }
            )
        }),
        ("A19b", ENTRY_CUSTODY, |e| {
            matches!(
                e,
                BodyError::UnknownDidDiscriminator {
                    field: DidDiscriminatorField::CustodyType,
                    ..
                }
            )
        }),
        ("A19c", ENTRY_ROLE, |e| {
            matches!(
                e,
                BodyError::UnknownDidDiscriminator {
                    field: DidDiscriminatorField::Role,
                    ..
                }
            )
        }),
        ("A19d", ENTRY_CONDITION, |e| {
            matches!(
                e,
                BodyError::UnknownDidDiscriminator {
                    field: DidDiscriminatorField::Condition,
                    ..
                }
            )
        }),
    ];
    for (name, at, expected) in patches {
        let unit = v41_key_state_wire(
            ring,
            |_| {},
            |wire| Wire::set(&mut wire.snapshot, entry_at(1, at), UNKNOWN_BYTE),
        )?;
        rows.push(v41_row(name, unit, Expect::Body(expected))?);
    }
    let service = service_role_at(&v41_changed()?);
    rows.push(v41_row(
        "A19e",
        v41_key_state_wire(
            ring,
            |_| {},
            |wire| Wire::set(&mut wire.snapshot, service, UNKNOWN_BYTE),
        )?,
        Expect::Body(|e| {
            matches!(
                e,
                BodyError::UnknownDidDiscriminator {
                    field: DidDiscriminatorField::ServiceKeyRole,
                    ..
                }
            )
        }),
    )?);

    Ok(rows)
}

fn key_state_header_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let mut rows = Vec::new();
    let header_rows: [HeaderCase; 5] = [
        (
            "A18a-short",
            |wire| {
                wire.forms = 0_u32.to_be_bytes().to_vec();
                Ok(())
            },
            |e| matches!(e, HeaderError::FormListLength(l) if l.indices == 1 && l.forms == 0),
        ),
        (
            "A18a-long",
            |wire| {
                wire.forms = vec![0, 0, 0, 2, 1, 1];
                Ok(())
            },
            |e| matches!(e, HeaderError::FormListLength(l) if l.indices == 1 && l.forms == 2),
        ),
        (
            "A18b",
            |wire| Wire::set(&mut wire.forms, 4, 0x03),
            |e| {
                matches!(
                    e,
                    HeaderError::UnknownDiscriminator {
                        field: HeaderDiscriminator::SignatureForm,
                        value: 0x03
                    }
                )
            },
        ),
        (
            "A19",
            |wire| Wire::set(&mut wire.head, KIND_AT, 0x05),
            |e| {
                matches!(
                    e,
                    HeaderError::UnknownDiscriminator {
                        field: HeaderDiscriminator::EventType,
                        value: 0x05
                    }
                )
            },
        ),
        (
            "A19a",
            |wire| Wire::set(&mut wire.head, STANDING_ROOT_AT, 0x03),
            |e| {
                matches!(
                    e,
                    HeaderError::UnknownDiscriminator {
                        field: HeaderDiscriminator::StandingRoot,
                        value: 0x03
                    }
                )
            },
        ),
    ];
    for (name, patch, expected) in header_rows {
        let unit = v41_key_state_wire(ring, |_| {}, patch)?;
        rows.push(v41_row(name, unit, Expect::Header(expected))?);
    }

    Ok(rows)
}

fn key_state_snapshot_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let (root, active) = v41_keys()?;
    let base = v41()?;
    let mut rows = Vec::new();
    rows.push(v41_row(
        "A21",
        v41_key_state(ring, |s| {
            s.keys = vec![
                root,
                entry(active.key, KeyRole::Active, KeyCondition::Retired),
            ];
            Ok(())
        })?,
        content(ContentDefect::ServiceRoleUnresolved),
    )?);
    for interval in [299, 604_801] {
        rows.push(v41_row(
            if interval == 299 { "A22a" } else { "A22b" },
            v41_key_state(ring, |s| {
                s.witnessing_interval = interval;
                Ok(())
            })?,
            content(ContentDefect::WitnessIntervalOutOfRange { interval }),
        )?);
    }
    rows.push(v41_row(
        "A23a",
        v41_key_state(ring, |s| {
            s.witnesses = (0..33_u8)
                .map(|n| Identifier::from_bytes([n; 32]))
                .collect();
            Ok(())
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
    )?);
    rows.push(v41_row(
        "A23b",
        v41_key_state(ring, |s| {
            let witness = *s.witnesses.first().ok_or("no witness")?;
            s.witnesses.push(witness);
            Ok(())
        })?,
        content(ContentDefect::NotDistinct {
            list: DistinctList::Witnesses,
        }),
    )?);
    rows.push(v41_row(
        "A24",
        key_state(ring, &base, v41_snapshot(3600)?, |_| {})?,
        content(ContentDefect::SnapshotUnchanged),
    )?);
    rows.push(v41_row(
        "A25",
        v41_key_state(ring, |s| {
            s.witnesses = vec![identifier(V41_IDENTIFIER)?];
            Ok(())
        })?,
        content(ContentDefect::WitnessNamesSubject),
    )?);
    rows.push(v41_row(
        "A26/C16-on-V41",
        a26_on_v41(ring)?,
        content(ContentDefect::TwoCurrentInRole {
            role: KeyRole::Active,
        }),
    )?);
    Ok(rows)
}

fn key_state_compromise_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let (root, active) = v41_keys()?;
    let new_active = point("pr3-active-2");
    let mut rows = Vec::new();
    rows.push(v41_row(
        "A29",
        v41_key_state(ring, |s| {
            s.delegator = Identifier::from_bytes([0x11; 32]);
            Ok(())
        })?,
        content(ContentDefect::NonzeroDelegator),
    )?);
    rows.push(v41_row(
        "A37",
        v41_key_state(ring, |s| {
            s.keys = vec![
                root,
                current(new_active, KeyRole::Active),
                KeyEntry {
                    condition: KeyCondition::Compromised,
                    compromised_from: 2,
                    ..active
                },
            ];
            Ok(())
        })?,
        content(ContentDefect::CompromisedFromAfterSequence {
            key: active.key,
            from: 2,
            sequence: 1,
        }),
    )?);
    Ok(rows)
}

fn key_state_drop_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let (root, active) = v41_keys()?;
    let new_active = point("pr3-active-2");
    let base = v41()?;
    let mut rows = Vec::new();
    rows.push(v41_row(
        "A39",
        v41_key_state(ring, |s| {
            s.keys = vec![
                root,
                current(NOT_A_POINT, KeyRole::Active),
                entry(active.key, KeyRole::Active, KeyCondition::Superseded),
            ];
            Ok(())
        })?,
        content(ContentDefect::InvalidPoint { key: NOT_A_POINT }),
    )?);
    rows.push(v41_row(
        "A42",
        v41_key_state(ring, |s| {
            s.keys = vec![root, current(new_active, KeyRole::Active)];
            Ok(())
        })?,
        content(ContentDefect::SilentDrop { key: active.key }),
    )?);
    rows.push(v41_row(
        "A43-superseded",
        v41_key_state(ring, |s| {
            s.keys = vec![
                root,
                entry(active.key, KeyRole::Active, KeyCondition::Superseded),
            ];
            Ok(())
        })?,
        content(ContentDefect::SupersededWithoutSuccessor { key: active.key }),
    )?);
    rows.push(v41_row(
        "A43-retired",
        v41_key_state(ring, |s| {
            s.keys = vec![
                root,
                current(new_active, KeyRole::Active),
                entry(active.key, KeyRole::Active, KeyCondition::Retired),
            ];
            Ok(())
        })?,
        content(ContentDefect::RetiredWithSuccessor { key: active.key }),
    )?);
    rows.push(v41_row(
        "A44",
        v41_key_state(ring, |s| {
            s.keys = vec![
                root,
                current(new_active, KeyRole::Active),
                entry(active.key, KeyRole::RootMember, KeyCondition::Superseded),
            ];
            Ok(())
        })?,
        content(ContentDefect::RoleChanged {
            key: active.key,
            installed: KeyRole::Active,
            listed: KeyRole::RootMember,
        }),
    )?);
    rows.push(v41_row(
        "A45",
        key_state(ring, &base, v41_changed()?, |p| {
            p.identifier = identifier(V42_IDENTIFIER).unwrap_or(Identifier::ZERO);
        })?,
        content(ContentDefect::IdentifierFieldMismatch),
    )?);
    rows.push(v41_row(
        "A46",
        v41_key_state(ring, |s| {
            s.keys = vec![
                current(new_active, KeyRole::Active),
                root,
                entry(active.key, KeyRole::Active, KeyCondition::Superseded),
            ];
            Ok(())
        })?,
        content(ContentDefect::SnapshotOrder { key: root.key }),
    )?);
    rows.push(v41_row(
        "A47",
        v41_key_state(ring, |s| {
            s.service_key_role = KeyRole::RootMember;
            Ok(())
        })?,
        content(ContentDefect::ServiceRoleNotActive {
            role: KeyRole::RootMember,
        }),
    )?);

    Ok(rows)
}

fn key_state_sentinel_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let base = v41()?;
    let mut rows = Vec::new();
    let sentinels: [SentinelCase; 4] = [
        ("A48-KeyState-5", 5, |p| {
            p.standing_root = Some(StandingRootDeclaration::CoSigns);
        }),
        ("A48-KeyState-8", 8, |p| {
            p.revealed_keys = vec![
                p.key_state
                    .as_ref()
                    .map_or([2; 33], |s| s.keys.first().map_or([2; 33], |e| e.key)),
            ];
        }),
        ("A48-KeyState-9", 9, |p| {
            p.installed_root_set = p.key_state.as_ref().map(KeyStateSnapshot::root_set);
        }),
        ("A48-KeyState-12", 12, |p| {
            p.continuation = Some(Continuation::Abandons);
        }),
    ];
    for (name, field, edit) in sentinels {
        rows.push(v41_row(
            name,
            key_state(ring, &base, v41_changed()?, edit)?,
            content(ContentDefect::SentinelHeld { field }),
        )?);
    }

    rows.push(v41_row(
        "A41e",
        {
            let mut inception = vector(super::fixtures::V41_PREIMAGE)?;
            inception.identifier = base.identifier;
            inception.sequence = 1;
            inception.predecessor_digest = base.head;
            on_v41(ring, &inception)?
        },
        content(ContentDefect::KindAtPosition {
            kind: EventKind::Inception,
        }),
    )?);

    rows.push(v41_row(
        "C13",
        {
            let stranger = super::chain_support::Key::labelled("pr3-stranger");
            let preimage = key_state_on(&base, v41_changed()?);
            let mut wire = Wire::of(&preimage);
            Wire::set(&mut wire.snapshot, entry_at(1, ENTRY_CUSTODY), 0x0A)?;
            unit(&wire.fields(), &[Some(&stranger)])?
        },
        Expect::VerifiedCount,
    )?);
    Ok(rows)
}

/// C16-on-V41: a `KeyState` on Vector 41 carrying two `Current` `#active`
/// keys (A26), signed by Vector 41's root.
pub fn a26_on_v41(ring: &Ring) -> Result<Vec<u8>, Error> {
    v41_key_state(ring, |s| {
        s.keys.push(current(point("pr3-active-2"), KeyRole::Active));
        Ok(())
    })
}

/// The rows on a `CommitmentRollover` after Vector 41.
fn rollover_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let mut rows = Vec::new();
    let v53 = vector(super::fixtures::V53_PREIMAGE)?;
    let fixed = match &v53.continuation {
        Some(Continuation::FixesCommitment(commitment)) => commitment.clone(),
        _ => return Err("Vector 53 fixes a commitment".into()),
    };
    let first = *fixed.commitments.first().ok_or("no commitment")?;

    let duplicates = [
        (
            "A4b",
            scp_did::CommitmentEntry {
                custody_type: CustodyType::Hsm,
                ..first
            },
        ),
        ("A4c", first),
    ];
    for (name, second) in duplicates {
        let preimage = v53_with(|p| {
            let mut commitment = fixed.clone();
            commitment.commitments.push(second);
            p.continuation = Some(Continuation::FixesCommitment(commitment));
        })?;
        rows.push(v41_row(
            name,
            on_v41(ring, &preimage)?,
            content(ContentDefect::NotDistinct {
                list: DistinctList::Commitments,
            }),
        )?);
    }
    rows.push(v41_row(
        "A6a",
        on_v41_wire(ring, &v53, |wire| {
            let mut continuation = vec![0x01];
            continuation.extend(list(17, 34));
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
    )?);
    rows.push(v41_row(
        "A6b",
        on_v41_wire(ring, &v53, |wire| {
            let mut indices = 17_u32.to_be_bytes().to_vec();
            indices.extend(0..17_u8);
            indices.extend_from_slice(&[0, 0, 0, 1, 0]);
            wire.indices = indices;
            Ok(())
        })?,
        Expect::Header(|e| {
            matches!(
                e,
                HeaderError::CountOverMax {
                    list: SignerList::Indices(SignerGroupRole::Reveal),
                    count: 17,
                    max: 16
                }
            )
        }),
    )?);
    rows.push(v41_row(
        "A9b",
        on_v41(
            ring,
            &v53_with(|p| {
                let mut commitment = fixed.clone();
                commitment.next_threshold = 2;
                p.continuation = Some(Continuation::FixesCommitment(commitment));
            })?,
        )?,
        content(ContentDefect::ThresholdOutOfRange {
            field: ThresholdField::Next,
            threshold: 2,
            size: 1,
        }),
    )?);

    Ok(rows)
}

fn rollover_reveal_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let v53 = vector(super::fixtures::V53_PREIMAGE)?;
    let mut rows = Vec::new();
    let stranger = point("pr3-stranger");
    rows.push(v41_row(
        "A11",
        on_v41(ring, &v53_with(|p| p.revealed_keys = vec![stranger])?)?,
        content(ContentDefect::RevealMismatch { index: 0 }),
    )?);
    rows.push(v41_row(
        "A11-keyless",
        on_v41(
            ring,
            &v53_with(|p| {
                p.revealed_keys = vec![stranger];
                if let Some(standing) = p.signer_groups.get_mut(1) {
                    *standing = group(&[]);
                }
            })?,
        )?,
        Expect::NamedCount,
    )?);
    let ter = v41_next()?;
    rows.push(v41_row(
        "A12",
        on_v41(ring, &v53_with(|p| p.revealed_keys = vec![ter, stranger])?)?,
        content(ContentDefect::RevealCountMismatch {
            indices: 1,
            keys: 2,
        }),
    )?);
    rows.push(v41_row(
        "A12-keyless",
        on_v41(
            ring,
            &v53_with(|p| {
                p.revealed_keys = vec![stranger, ter];
                if let Some(standing) = p.signer_groups.get_mut(1) {
                    *standing = group(&[]);
                }
            })?,
        )?,
        Expect::NamedCount,
    )?);
    rows.push(v41_row(
        "A17-field-12",
        on_v41_wire(ring, &v53, |wire| {
            // 0x01, count, then the entry's commitment, custody, algorithm.
            Wire::set(&mut wire.continuation, 1 + 4 + 32 + 1, UNKNOWN_BYTE)
        })?,
        Expect::Body(|e| {
            matches!(
                e,
                BodyError::UnknownDidDiscriminator {
                    field: DidDiscriminatorField::KeyAlgorithm,
                    ..
                }
            )
        }),
    )?);
    rows.push(v41_row(
        "A19f",
        on_v41_wire(ring, &v53, |wire| {
            Wire::set(&mut wire.continuation, 0, 0x02)
        })?,
        Expect::Body(|e| matches!(e, BodyError::UnknownContinuation { value: 0x02 })),
    )?);
    let root = reference()?.point;
    rows.push(v41_row(
        "A28b",
        on_v41(
            ring,
            &v53_with(|p| p.continuation = Some(fixes(&[root], 1)))?,
        )?,
        content(ContentDefect::CommitmentToInstalledKey {
            commitment: prerotation_commitment(&root),
        }),
    )?);
    rows.push(v41_row(
        "A32",
        on_v41(ring, &v53_with(|p| p.continuation = None)?)?,
        content(ContentDefect::ContinuationMissing),
    )?);

    Ok(rows)
}

fn rollover_sentinel_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let v53 = vector(super::fixtures::V53_PREIMAGE)?;
    let mut rows = Vec::new();
    let sentinels: [SentinelCase; 4] = [
        ("A48-Rollover-5", 5, |p| {
            p.standing_root = Some(StandingRootDeclaration::Lost);
        }),
        ("A48-Rollover-9", 9, |p| {
            p.installed_root_set = Some(InstalledRootSet {
                members: vec![[2; 33]],
                threshold: 1,
            });
        }),
        ("A48-Rollover-10", 10, |p| {
            p.key_state = vector(super::fixtures::V41_PREIMAGE)
                .ok()
                .and_then(|v41| v41.key_state);
        }),
        ("A48-Rollover-11", 11, |p| p.seals = vec![[0x22; 32]]),
    ];
    for (name, field, edit) in sentinels {
        let preimage = v53_with(edit)?;
        // Field 5 `Lost` makes the decoder read a rollover's groups as a
        // recovery's; keep the rollover's two groups on the wire.
        rows.push(v41_row(
            name,
            on_v41(ring, &preimage)?,
            content(ContentDefect::SentinelHeld { field }),
        )?);
    }

    // Criterion 34: a field 8 whose count runs past the remaining bytes.
    let undecodable = |wire: &mut Wire| {
        Wire::set(&mut wire.revealed, 0, 0x7F)?;
        Ok(())
    };
    rows.push(v41_row(
        "field-8-undecodable",
        on_v41_wire(ring, &v53, undecodable)?,
        Expect::Body(|e| {
            matches!(
                e,
                BodyError::CountOverMax {
                    list: BodyList::RevealedKeys,
                    ..
                } | BodyError::CountOverRemaining {
                    list: BodyList::RevealedKeys,
                    ..
                }
            )
        }),
    )?);
    let reveal_only = v53_with(|p| {
        if let Some(standing) = p.signer_groups.get_mut(1) {
            *standing = group(&[]);
        }
    })?;
    rows.push(v41_row(
        "field-8-undecodable-reveal-only",
        on_v41_wire(ring, &reveal_only, undecodable)?,
        Expect::NamedCount,
    )?);
    Ok(rows)
}

/// The rows on a `RootRecovery` after Vector 41.
fn recovery_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let mut rows = Vec::new();
    let v54 = vector(V54_PREIMAGE)?;
    let snapshot54 = v54
        .key_state
        .clone()
        .ok_or("Vector 54 carries a snapshot")?;
    let k_prime = point("scp-25-recovery-cosigns-root");
    let k_two = point("pr3-kprime-2");

    // A1's threshold-signed fixture: K′ is 2-of-2 and its group names one.
    let mut two_of_two = snapshot54;
    two_of_two
        .keys
        .insert(1, current(k_two, KeyRole::RootMember));
    two_of_two.root_threshold = 2;
    let preimage = v54_with(|p| set_snapshot(p, two_of_two.clone()))?;
    rows.push(v41_row(
        "A1-recovery",
        on_v41(ring, &preimage)?,
        content(ContentDefect::IndexCountBelowThreshold {
            role: SignerGroupRole::ReplacementRoot,
            named: 1,
            threshold: 2,
        }),
    )?);
    rows.push(v41_row(
        "A4a",
        on_v41(
            ring,
            &v54_with(|p| {
                p.installed_root_set = Some(InstalledRootSet {
                    members: vec![k_prime, k_prime],
                    threshold: 1,
                });
            })?,
        )?,
        content(ContentDefect::NotDistinct {
            list: DistinctList::RootSet,
        }),
    )?);
    rows.push(v41_row(
        "A5",
        on_v41_wire(ring, &v54, |wire| {
            let mut installed = list(17, 33);
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
    )?);
    rows.push(v41_row(
        "A9a",
        on_v41(
            ring,
            &v54_with(|p| {
                p.installed_root_set = Some(InstalledRootSet {
                    members: vec![k_prime],
                    threshold: 2,
                });
            })?,
        )?,
        content(ContentDefect::ThresholdOutOfRange {
            field: ThresholdField::Root,
            threshold: 2,
            size: 1,
        }),
    )?);
    let preimage = v54_with(|p| {
        set_snapshot(p, two_of_two.clone());
        if let Some(k_group) = p.signer_groups.get_mut(1) {
            *k_group = group(&[0, 1]);
        }
    })?;
    rows.push(v41_row(
        "A20",
        on_v41(ring, &preimage)?,
        content(ContentDefect::NextThresholdBelowRoot {
            next_threshold: 1,
            root_threshold: 2,
        }),
    )?);
    Ok(rows)
}

fn recovery_continuation_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let k_prime = point("scp-25-recovery-cosigns-root");
    Ok(vec![
        v41_row(
            "A28a",
            on_v41(
                ring,
                &v54_with(|p| p.continuation = Some(fixes(&[k_prime], 1)))?,
            )?,
            content(ContentDefect::InstalledKeyCommitted { key: k_prime }),
        )?,
        v41_row(
            "A33",
            on_v41(
                ring,
                &v54_with(|p| p.continuation = Some(Continuation::Abandons))?,
            )?,
            content(ContentDefect::RecoveryAbandons),
        )?,
    ])
}

fn recovery_root_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let v54 = vector(V54_PREIMAGE)?;
    let snapshot54 = v54
        .key_state
        .clone()
        .ok_or("Vector 54 carries a snapshot")?;
    let k_prime = point("scp-25-recovery-cosigns-root");
    let k_two = point("pr3-kprime-2");
    let mut rows = Vec::new();
    // Criterion 7: field 9 differs from the snapshot's root in members, in
    // member order, and in threshold.
    let mut two_members = snapshot54.clone();
    two_members
        .keys
        .insert(1, current(k_two, KeyRole::RootMember));
    let root_set = |members: Vec<[u8; 33]>, threshold| InstalledRootSet { members, threshold };
    let differences: [(&'static str, InstalledRootSet, &KeyStateSnapshot); 3] = [
        ("A38-members", root_set(vec![k_two], 1), &snapshot54),
        ("A38-order", root_set(vec![k_two, k_prime], 1), &two_members),
        (
            "A38-threshold",
            root_set(vec![k_prime, k_two], 2),
            &two_members,
        ),
    ];
    for (name, installed, listed) in differences {
        let count = u8::try_from(installed.members.len())?;
        let preimage = v54_with(|p| {
            p.key_state = Some(listed.clone());
            if let Some(k_group) = p.signer_groups.get_mut(1) {
                *k_group = group(&(0..count).collect::<Vec<_>>());
            }
            p.installed_root_set = Some(installed);
        })?;
        rows.push(v41_row(
            name,
            on_v41(ring, &preimage)?,
            content(ContentDefect::InstalledRootMismatch),
        )?);
    }
    rows.push(v41_row(
        "A48-Recovery-11",
        on_v41(ring, &v54_with(|p| p.seals = vec![[0x22; 32]])?)?,
        content(ContentDefect::SentinelHeld { field: 11 }),
    )?);
    rows.push(v41_row(
        "A19a-recovery",
        on_v41_wire(ring, &v54, |wire| {
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
    )?);
    rows.push(v41_row(
        "recovery-without-standing-root",
        on_v41_wire(ring, &v54, |wire| {
            Wire::set(&mut wire.head, STANDING_ROOT_AT, 0x00)
        })?,
        Expect::Header(|e| matches!(e, HeaderError::RootRecoveryWithoutStandingRoot)),
    )?);

    Ok(rows)
}

fn recovery_signature_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let v54 = vector(V54_PREIMAGE)?;
    let mut rows = Vec::new();
    // Criterion 18: each group verifies against its own key set.
    let old_root = reference()?;
    let ter = tertiary()?;
    let k_key = super::chain_support::Key::labelled("scp-25-recovery-cosigns-root");
    let fields = Wire::of(&v54).fields();
    rows.push(v41_row(
        "K′-group-signed-by-standing-root",
        unit(&fields, &[Some(&ter), Some(&old_root), Some(&old_root)])?,
        Expect::Signature(SignerGroupRole::ReplacementRoot, 0),
    )?);
    rows.push(v41_row(
        "C11",
        unit(&fields, &[Some(&ter), Some(&k_key), Some(&k_key)])?,
        Expect::Signature(SignerGroupRole::StandingRoot, 0),
    )?);
    let good = on_v41(ring, &v54)?;
    let signature_at = 4 + signed(&fields).len();
    rows.push(v41_row(
        "C14",
        super::chain_support::flip(&good, signature_at + 64 + 10)?,
        Expect::Signature(SignerGroupRole::ReplacementRoot, 0),
    )?);
    rows.push(v41_row(
        "C15",
        super::chain_support::flip(&good, signature_at + 10)?,
        Expect::Signature(SignerGroupRole::Reveal, 0),
    )?);
    let mut stripped = good.clone();
    stripped.truncate(good.len() - 64);
    rows.push(v41_row("C4", stripped, Expect::Walk)?);

    // C7: Vector 55 with a third group's signature inside its unit.
    let v55 = v41_v55()?;
    let mut third = v55.units.last().ok_or("no V55 unit")?.clone();
    third.extend_from_slice(&[0x11; 64]);
    rows.push(v41_row("C7", third, Expect::Walk)?);

    // C8: a keyless `{Lost}` whose reveal does not match Vector 41's
    // commitment; K′ never counts.
    let stranger = point("pr3-stranger");
    rows.push(v41_row(
        "C8",
        on_v41(
            ring,
            &v55_with(|p| {
                p.revealed_keys = vec![stranger];
            })?,
        )?,
        Expect::NamedCount,
    )?);
    Ok(rows)
}

/// Rows whose base is longer than Vector 41.
fn chained_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let (root, active) = v41_keys()?;
    let ter = v41_next()?;
    let mut rows = Vec::new();

    // A27: a key revealed by Vector 53 installed as `#active`.
    let base = v41_v53()?;
    let mut installs_revealed = v41_snapshot(3600)?;
    installs_revealed.keys = vec![
        root,
        current(ter, KeyRole::Active),
        entry(active.key, KeyRole::Active, KeyCondition::Superseded),
    ];
    let unit = key_state(ring, &base, installs_revealed, |_| {})?;
    rows.push(row(
        "A27",
        base.clone(),
        unit,
        content(ContentDefect::InstalledKeyRevealed { key: ter }),
    ));

    // A36: a commitment to the key Vector 53 revealed.
    let next = point("scp-25-rollover-next");
    let rollover = EventPreimage::commitment_rollover(scp_kel::CommitmentRolloverFields {
        identifier: base.identifier,
        sequence: 2,
        predecessor_digest: base.head,
        reveal_group: group(&[0]),
        standing_root_group: group(&[0]),
        revealed_keys: vec![next],
        continuation: fixes(&[ter], 1),
    });
    rows.push(row(
        "A36",
        base.clone(),
        sign_on(ring, &base, &rollover)?,
        content(ContentDefect::CommitmentToRevealedKey {
            commitment: prerotation_commitment(&ter),
        }),
    ));

    // A34: any event after an abandonment.
    let abandoned = v41_v68()?;
    rows.push(row(
        "A34",
        abandoned.clone(),
        key_state(ring, &abandoned, v41_changed()?, |_| {})?,
        content(ContentDefect::AfterAbandonment),
    ));

    Ok(rows)
}

fn chained_reinstall_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let (root, active) = v41_keys()?;
    let ter = v41_next()?;
    let mut rows = Vec::new();
    // A35: a key a first `KeyState` dropped is installed again.
    let v41 = v41()?;
    let new_active = point("pr3-active-2");
    let mut swap = v41_snapshot(3600)?;
    swap.keys = vec![
        root,
        current(new_active, KeyRole::Active),
        entry(active.key, KeyRole::Active, KeyCondition::Superseded),
    ];
    let first = key_state_on(&v41, swap.clone());
    let first_fields = Wire::of(&first).fields();
    let swapped = v41.then(
        &first_fields,
        sign_on(ring, &v41, &first)?,
        v41.root.clone(),
    );
    let mut back = swap;
    back.keys = vec![
        root,
        current(active.key, KeyRole::Active),
        entry(new_active, KeyRole::Active, KeyCondition::Superseded),
    ];
    rows.push(row(
        "A35",
        swapped.clone(),
        key_state(ring, &swapped, back, |_| {})?,
        content(ContentDefect::KeyInstalledTwice { key: active.key }),
    ));

    // Criterion 16: a `CommitmentRollover` committing to the `#active` key
    // an earlier `KeyState` installed.
    let rollover = EventPreimage::commitment_rollover(scp_kel::CommitmentRolloverFields {
        identifier: swapped.identifier,
        sequence: 2,
        predecessor_digest: swapped.head,
        reveal_group: group(&[0]),
        standing_root_group: group(&[0]),
        revealed_keys: vec![ter],
        continuation: fixes(&[new_active], 1),
    });
    rows.push(row(
        "rollover-commits-to-installed-active",
        swapped.clone(),
        sign_on(ring, &swapped, &rollover)?,
        content(ContentDefect::CommitmentToInstalledKey {
            commitment: prerotation_commitment(&new_active),
        }),
    ));

    // Criterion 16: a `KeyState` installing an unrevealed member of the
    // standing next set as `#active`.
    let mut installs_next = v41_snapshot(3600)?;
    installs_next.keys = vec![
        root,
        current(ter, KeyRole::Active),
        entry(active.key, KeyRole::Active, KeyCondition::Superseded),
    ];
    rows.push(row(
        "key-state-installs-unrevealed-next",
        v41.clone(),
        key_state(ring, &v41, installs_next, |_| {})?,
        content(ContentDefect::InstalledKeyCommitted { key: ter }),
    ));

    Ok(rows)
}

fn chained_f1_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let mut rows = Vec::new();
    // Criterion 16 on F1, whose next set holds two members at threshold 1.
    let f1 = f1(ring)?;
    let f1_snapshot = super::chain_support::f1_inception()?
        .key_state
        .ok_or("F1 carries a snapshot")?;
    let next_0 = point("pr3-next-0");
    let next_1 = point("pr3-next-1");
    // A `RootRecovery` installing into K′ the unrevealed member.
    let recovery = Recovery {
        base: &f1,
        previous: &f1_snapshot,
        signing: StandingRootSigning::CoSigns {
            standing_root_group: group(&[0]),
        },
        reveal: &[0],
        revealed: vec![next_0],
        k_prime: &[next_1],
        k_threshold: 1,
        active: point("pr3-f1-z"),
        continuation: fixes(&[point("pr3-stranger")], 1),
    }
    .preimage()?;
    rows.push(row(
        "recovery-installs-unrevealed-next",
        f1.clone(),
        sign_on(ring, &f1, &recovery)?,
        content(ContentDefect::InstalledKeyCommitted { key: next_1 }),
    ));
    // A `KeyState` installing as `#active` a key whose commitment a list
    // an earlier rollover superseded.
    let rollover = EventPreimage::commitment_rollover(scp_kel::CommitmentRolloverFields {
        identifier: f1.identifier,
        sequence: 1,
        predecessor_digest: f1.head,
        reveal_group: group(&[0]),
        standing_root_group: group(&[0]),
        revealed_keys: vec![next_0],
        continuation: fixes(&[point("pr3-f1-z")], 1),
    });
    let rolled = f1.then(
        &Wire::of(&rollover).fields(),
        sign_on(ring, &f1, &rollover)?,
        f1.root.clone(),
    );
    let f1_root = point("pr3-f1-root");
    let f1_active = point("pr3-f1-active");
    let mut superseded = f1_snapshot;
    superseded.keys = vec![
        current(f1_root, KeyRole::RootMember),
        current(next_1, KeyRole::Active),
        entry(f1_active, KeyRole::Active, KeyCondition::Superseded),
    ];
    rows.push(row(
        "key-state-installs-superseded-commitment",
        rolled.clone(),
        key_state(ring, &rolled, superseded, |_| {})?,
        content(ContentDefect::InstalledKeyCommitted { key: next_1 }),
    ));
    // The base chains are valid.
    chain_of(&rolled)?;

    Ok(rows)
}

fn chained_f2_fx_rows(ring: &Ring) -> Result<Vec<Row>, Error> {
    let mut rows = Vec::new();
    // A40: a `{Lost}` whose reveal meets the threshold it fixes, 1, and not
    // F2's standing next threshold, 2.
    let f2 = f2(ring)?;
    let f2_snapshot = f2_inception()?.key_state.ok_or("F2 carries a snapshot")?;
    let lost = Recovery {
        base: &f2,
        previous: &f2_snapshot,
        signing: StandingRootSigning::Lost,
        reveal: &[0],
        revealed: vec![point("pr3-f2-next-0")],
        k_prime: &[point("pr3-f2-kprime")],
        k_threshold: 1,
        active: point("pr3-f2-new-active"),
        continuation: fixes(&[point("pr3-stranger")], 1),
    }
    .preimage()?;
    rows.push(row(
        "A40",
        f2.clone(),
        sign_on(ring, &f2, &lost)?,
        Expect::NamedCount,
    ));

    // C16: F2's 1-of-2 root names both indices, one signature verifies and
    // the other is flipped; step 8 runs before step 9.
    let mut two_active = f2_snapshot;
    two_active
        .keys
        .push(current(point("pr3-active-3"), KeyRole::Active));
    let preimage = {
        let mut p = key_state_on(&f2, two_active);
        p.signer_groups = vec![group(&[0, 1])];
        p
    };
    let signed_unit = sign_on(ring, &f2, &preimage)?;
    let at = 4 + signed(&Wire::of(&preimage).fields()).len() + 64 + 10;
    rows.push(row(
        "C16",
        f2,
        super::chain_support::flip(&signed_unit, at)?,
        content(ContentDefect::TwoCurrentInRole {
            role: KeyRole::Active,
        }),
    ));

    // A39 on FX: a reveal of a string no point encodes, which matches FX's
    // commitment.
    let fx = fx(ring)?;
    let reveal_invalid = |standing: &[u8]| {
        EventPreimage::commitment_rollover(scp_kel::CommitmentRolloverFields {
            identifier: fx.identifier,
            sequence: 1,
            predecessor_digest: fx.head,
            reveal_group: group(&[0]),
            standing_root_group: group(standing),
            revealed_keys: vec![NOT_A_POINT],
            continuation: fixes(&[point("pr3-stranger")], 1),
        })
    };
    rows.push(row(
        "A39-reveal",
        fx.clone(),
        sign_on(ring, &fx, &reveal_invalid(&[0]))?,
        content(ContentDefect::InvalidPoint { key: NOT_A_POINT }),
    ));
    rows.push(row(
        "A39-reveal-only",
        fx.clone(),
        sign_on(ring, &fx, &reveal_invalid(&[]))?,
        Expect::VerifiedCount,
    ));

    // A8: a `KeyState` on Vector 41 one seal over `MAX_EVENT_BYTES`.
    let (over, _) = seal_bound(ring)?;
    rows.push(row(
        "A8",
        v41()?,
        over,
        Expect::Header(|e| {
            matches!(
                e,
                HeaderError::EventTooLong {
                    encoded_len: 65_568
                }
            )
        }),
    ));
    Ok(rows)
}

/// The `KeyState` units on Vector 41 one seal over and exactly at
/// `MAX_EVENT_BYTES`: the encoded length is the signed preimage plus 64
/// bytes for the one raw root index.
pub fn seal_bound(ring: &Ring) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let base = v41()?;
    let empty = key_state_on(&base, v41_changed()?);
    let empty_len = signed(&Wire::of(&empty).fields()).len() + 64;
    let room = 65_536 - empty_len;
    if !room.is_multiple_of(32) {
        return Err(format!("{room} bytes of room is not a whole number of seals").into());
    }
    let at = |seals: usize| {
        let mut preimage = empty.clone();
        preimage.seals = (0..seals)
            .map(|n| {
                let mut seal = [0x33; 32];
                seal[..8].copy_from_slice(&(n as u64).to_be_bytes());
                seal
            })
            .collect();
        sign_on(ring, &base, &preimage)
    };
    Ok((at(room / 32 + 1)?, at(room / 32)?))
}

/// Byte offsets inside a unit: the length prefix, then the separator, then
/// field 4 at offset 41 of the head.
const SEPARATOR_AT: usize = 4;
const PREDECESSOR_AT: usize = 4 + 17 + 41;

/// Rows on Vector 50's own unit, served after the wrong base or with a
/// byte flipped.
fn vector_rows() -> Result<Vec<Row>, Error> {
    let v50 = v41_v50()?.units.last().ok_or("no V50 unit")?.clone();
    let signature_at = 4 + signed_of(&v50)?.len();
    Ok(vec![
        v41_row(
            "C2",
            super::chain_support::flip(&v50, PREDECESSOR_AT)?,
            Expect::Predecessor,
        )?,
        row("C2b", v42()?, v50.clone(), Expect::Predecessor),
        v41_row(
            "C3",
            super::chain_support::flip(&v50, signature_at + 10)?,
            Expect::VerifiedCount,
        )?,
        v41_row(
            "C10",
            super::chain_support::flip(&v50, SEPARATOR_AT)?,
            Expect::Separator,
        )?,
    ])
}

/// One group of rows, built over the shared key ring.
type Builder = fn(&Ring) -> Result<Vec<Row>, Error>;

/// The rows of this module.
pub fn rows() -> Result<Vec<Row>, Error> {
    let ring = Ring::new()?;
    let mut rows = vector_rows()?;
    let builders: [Builder; 18] = [
        key_state_rows,
        key_state_discriminator_rows,
        key_state_header_rows,
        key_state_snapshot_rows,
        key_state_compromise_rows,
        key_state_drop_rows,
        key_state_sentinel_rows,
        rollover_rows,
        rollover_reveal_rows,
        rollover_sentinel_rows,
        recovery_rows,
        recovery_continuation_rows,
        recovery_root_rows,
        recovery_signature_rows,
        chained_rows,
        chained_reinstall_rows,
        chained_f1_rows,
        chained_f2_fx_rows,
    ];
    for build in builders {
        rows.extend(build(&ring)?);
    }
    Ok(rows)
}

#[test]
fn every_defect_past_the_inception_is_discarded_at_its_step() -> TestResult {
    for row in rows()? {
        check(&row)?;
    }
    Ok(())
}

#[test]
fn a_key_state_at_max_event_bytes_is_valid() -> TestResult {
    let ring = Ring::new()?;
    let (_, at_bound) = seal_bound(&ring)?;
    let base = v41()?;
    let (chain, discarded) = valid(&base.identifier, &base.with(&at_bound))?;
    assert!(discarded.is_empty(), "{discarded:?}");
    assert_eq!(chain.head_digest(), digest_of(signed_of(&at_bound)?));
    Ok(())
}

/// Vector 69 drops Vector 41's `#active` key as `Compromised` from its own
/// sequence, N = sequence, which R3 accepts.
#[test]
fn compromised_from_the_event_sequence_is_valid() -> TestResult {
    let base = super::chain_support::v41_v69()?;
    let chain = chain_of(&base)?;
    assert_eq!(chain.head_sequence(), 1);
    Ok(())
}
