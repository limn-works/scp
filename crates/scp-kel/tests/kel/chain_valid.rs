//! `validate_entry` on chains R3 accepts (`09-security-model.md` §9.7.4.2
//! R3): spec 25's chains, a key state signed by the root a recovery
//! installed, every spec 25 change as R10 reports it, the unit-by-unit
//! equivalence of `extend`, and `prefix`.

use scp_did::{
    CommitmentEntry, CustodyType, FixedCommitment, Identifier, KeyAlgorithm, KeyCondition,
    KeyEntry, KeyRole,
};
use scp_kel::{
    ChangeEffect, CheckStep, Continuation, Discarded, EntryValidation, EntryVerdict, EventKind,
    InstalledRootSet, NamedKey, SignerGroupRole, SignerGroupSpec, ValidatedChain, ValidatedChange,
    validate_entry, validate_inception,
};

use super::chain_support::{
    Base, Error, Ring, Wire, current, digest_of, entry, f3, f3_inception, group, key_state_on,
    point, sha256, sign_on, signed, signed_of, slots, unit, v41, v41_v50, v41_v53, v41_v54,
    v41_v55, v41_v68, v41_v69, v42,
};
use super::fixtures::{
    TestResult, V41_ACTIVE, V41_DIGEST, V41_ROOT, V41_WITNESS, V42_DIGEST, V47A_POINT, V50_DIGEST,
    V51_DIGEST, V51_IDENTIFIER, V51_INCEPTION_DIGEST, V51_INCEPTION_PREIMAGE,
    V51_INCEPTION_SIGNATURE, V51_KEYS, V51_PREIMAGE, V51_PREROTATION, V51_SIGNATURE, V51_WITNESS,
    V53_DIGEST, V54_DIGEST, V55_DIGEST, V68_DIGEST, V69_ACTIVE, V69_DIGEST, array, bytes,
    event_unit, identifier,
};

/// The one chain and the discards of a `Valid` verdict holding exactly one
/// path, or the validation as an error.
pub fn valid(
    identifier: &Identifier,
    units: &[&[u8]],
) -> Result<(ValidatedChain, Vec<Discarded>), Error> {
    let EntryValidation { verdict, discarded } = validate_entry(identifier, units);
    let EntryVerdict::Valid { chains } = &verdict else {
        return Err(format!("expected Valid, got {verdict:?} with {discarded:?}").into());
    };
    let mut paths = chains.iter();
    match (paths.next(), paths.next()) {
        (Some(chain), None) => Ok((chain.clone(), discarded)),
        _ => Err(format!("expected one chain, got {chains:?}").into()),
    }
}

/// The base chain, validated with no discard.
pub fn chain_of(base: &Base) -> Result<ValidatedChain, Error> {
    let (chain, discarded) = valid(&base.identifier, &base.refs())?;
    if !discarded.is_empty() {
        return Err(format!("{}: discards {discarded:?}", base.name).into());
    }
    Ok(chain)
}

/// [Vector 51's inception, Vector 51].
pub fn v51_chain() -> Result<Base, Error> {
    Ok(Base {
        name: "V51i,V51",
        identifier: identifier(V51_IDENTIFIER)?,
        units: vec![
            event_unit(V51_INCEPTION_PREIMAGE, V51_INCEPTION_SIGNATURE)?,
            event_unit(V51_PREIMAGE, V51_SIGNATURE)?,
        ],
        head: digest_of(&bytes(V51_PREIMAGE)?),
        root: Vec::new(),
    })
}

/// A `KeyState` at sequence 2 after Vector 54, signed by K′.
fn v54_then_key_state(ring: &Ring) -> Result<(Base, Vec<u8>), Error> {
    let base = v41_v54()?;
    let k_prime = point("scp-25-recovery-cosigns-root");
    let active = point("scp-25-recovery-cosigns-active");
    let mut snapshot = super::chain_support::snapshot(
        vec![
            current(k_prime, KeyRole::RootMember),
            current(active, KeyRole::Active),
        ],
        1,
    )?;
    snapshot.witnessing_interval = 7200;
    let preimage = key_state_on(&base, snapshot);
    let fields = Wire::of(&preimage).fields();
    let unit = unit(&fields, &slots(ring, &preimage, &base.root))?;
    Ok((base, unit))
}

fn assert_head(base: &Base, digest_hex: &str) -> TestResult {
    let chain = chain_of(base)?;
    let digest: [u8; 32] = array(digest_hex)?;
    assert_eq!(chain.head_digest(), digest, "{}", base.name);
    assert_eq!(chain.head_digest(), base.head, "{}", base.name);
    assert_eq!(chain.head_sequence(), base.len() - 1, "{}", base.name);
    assert_eq!(chain.identifier(), base.identifier, "{}", base.name);
    Ok(())
}

#[test]
fn spec_25_chains_are_valid() -> TestResult {
    assert_head(&v41()?, V41_DIGEST)?;
    assert_head(&v42()?, V42_DIGEST)?;
    assert_head(&v41_v50()?, V50_DIGEST)?;
    assert_head(&v41_v53()?, V53_DIGEST)?;
    assert_head(&v41_v54()?, V54_DIGEST)?;
    assert_head(&v41_v55()?, V55_DIGEST)?;
    assert_head(&v41_v68()?, V68_DIGEST)?;
    assert_head(&v41_v69()?, V69_DIGEST)?;
    assert_head(&v51_chain()?, V51_DIGEST)?;
    Ok(())
}

/// The root a `RootRecovery` installs anchors the next event: K′ signs a
/// key state after Vector 54, and Vector 41's root signs nothing there.
#[test]
fn recovery_root_anchors_the_next_event() -> TestResult {
    let ring = Ring::new()?;
    let (base, signed_by_k_prime) = v54_then_key_state(&ring)?;
    let fields = signed_of(&signed_by_k_prime)?
        .get(super::chain_support::SEPARATOR.len()..)
        .ok_or("short")?
        .to_vec();
    let (chain, discarded) = valid(&base.identifier, &base.with(&signed_by_k_prime))?;
    assert!(discarded.is_empty(), "{discarded:?}");
    assert_eq!(chain.head_digest(), digest_of(&signed(&fields)));
    assert_eq!(chain.head_sequence(), 2);

    let old_root = super::chain_support::reference()?;
    let signed_by_old_root = unit(&fields, &[Some(&old_root)])?;
    let (chain, discarded) = valid(&base.identifier, &base.with(&signed_by_old_root))?;
    assert_eq!(chain.head_digest(), base.head);
    let [discard] = discarded.as_slice() else {
        return Err(format!("{discarded:?}").into());
    };
    assert_eq!(discard.stage(), CheckStep::VerifiedCount);
    assert_eq!(discard.served_index(), 2);
    assert_eq!(discard.read_for(), Some(2));
    Ok(())
}

/// `extend` unit by unit reaches the chain `validate_entry` returns, and
/// `prefix(p)` is the whole chain the first `p + 1` units validate to, for
/// every `p`.
#[test]
fn extend_and_prefix_agree_with_validate_entry() -> TestResult {
    let ring = Ring::new()?;
    let (after_v54, key_state) = v54_then_key_state(&ring)?;
    let mut three = after_v54;
    three.name = "V41,V54,KeyState";
    three.units.push(key_state);
    for base in [
        v41_v50()?,
        v41_v53()?,
        v41_v54()?,
        v41_v55()?,
        v41_v68()?,
        v41_v69()?,
        v51_chain()?,
        three,
    ] {
        let whole = chain_of(&base)?;
        let first = base.units.first().ok_or("no inception")?;
        let mut chain = chain_of(&Base {
            units: vec![first.clone()],
            ..base.clone()
        })?;
        for unit in base.units.iter().skip(1) {
            chain = chain
                .extend(unit)
                .map_err(|(_, discarded)| format!("{discarded:?}"))?;
        }
        assert_eq!(chain, whole, "{}", base.name);
        for p in 0..base.len() {
            let kept = usize::try_from(p + 1)?;
            let truncated = Base {
                units: base.units.get(..kept).ok_or("short")?.to_vec(),
                ..base.clone()
            };
            assert_eq!(
                whole.prefix(p),
                Some(chain_of(&truncated)?),
                "{} at {p}",
                base.name
            );
        }
        assert_eq!(whole.prefix(base.len()), None, "{}", base.name);
    }
    Ok(())
}

/// `SHA-256("SCP-PREROTATION-COMMITMENT-V1:" ‖ point)`, computed here.
fn commitment_to(point: &[u8; 33]) -> [u8; 32] {
    sha256(&[b"SCP-PREROTATION-COMMITMENT-V1:", point])
}

/// One `Passkey` `EcdsaP256Sha256` commitment to `point` at next threshold 1.
fn fixes_one(point: &[u8; 33]) -> Continuation {
    Continuation::FixesCommitment(FixedCommitment {
        commitments: vec![CommitmentEntry {
            commitment: commitment_to(point),
            custody_type: CustodyType::Passkey,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        }],
        next_threshold: 1,
    })
}

/// A group of `role` over `keys` at indices 0 upward, threshold 1, naming
/// index 0.
fn group_of(role: SignerGroupRole, keys: &[[u8; 33]]) -> Result<SignerGroupSpec, Error> {
    Ok(SignerGroupSpec {
        role,
        threshold: 1,
        key_set: keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Ok(NamedKey {
                    index: u8::try_from(index)?,
                    key: *key,
                })
            })
            .collect::<Result<_, Error>>()?,
        indices: vec![0],
    })
}

fn root_of(members: &[[u8; 33]]) -> InstalledRootSet {
    InstalledRootSet {
        members: members.to_vec(),
        threshold: 1,
    }
}

/// What spec 25 states about one change.
struct Expected {
    digest_hex: &'static str,
    signers: Vec<SignerGroupSpec>,
    effect: ChangeEffect,
}

fn assert_change(
    name: &str,
    change: &ValidatedChange,
    signed: &[u8],
    expected: &Expected,
) -> TestResult {
    let digest: [u8; 32] = array(expected.digest_hex)?;
    assert_eq!(digest, sha256(&[signed]), "{name}");
    assert_eq!(change.preimage(), signed, "{name}");
    assert_eq!(change.digest(), digest, "{name}");
    let challenge = [b"SCP-KEY-EVENT-V1:".as_slice(), digest.as_slice()].concat();
    assert_eq!(
        change.key_event_challenge().as_slice(),
        challenge.as_slice(),
        "{name}"
    );
    assert_eq!(change.signers(), expected.signers.as_slice(), "{name}");
    assert_eq!(change.effect(), &expected.effect, "{name}");
    Ok(())
}

/// The effect of a change at sequence 1 on Vector 41's identity.
fn on_v41(
    kind: EventKind,
    installed_keys: Vec<KeyEntry>,
    dropped_keys: Vec<KeyEntry>,
    continuation: Option<Continuation>,
    root_after: InstalledRootSet,
) -> Result<ChangeEffect, Error> {
    let witnesses = vec![identifier(V41_WITNESS)?];
    Ok(ChangeEffect {
        kind,
        sequence: 1,
        installed_keys,
        dropped_keys,
        continuation,
        root_before: Some(root_of(&[array(V41_ROOT)?])),
        root_after,
        witnesses_before: Some(witnesses.clone()),
        witnesses_after: witnesses,
    })
}

/// R10 on every spec 25 change past the inception: `validate_change` on the
/// chain before each later event reports the digest, the challenge, every
/// signer group's key set and the effect the vectors state.
#[test]
fn every_spec_25_change_reports_what_the_vector_states() -> TestResult {
    for (base, expected) in spec_25_changes()? {
        let whole = chain_of(&base)?;
        let before = whole.prefix(base.len() - 2).ok_or("no prefix")?;
        let last = base.units.last().ok_or("no unit")?;
        let signed = signed_of(last)?;
        let change = before
            .validate_change(signed)
            .map_err(|discard| format!("{}: {discard:?}", base.name))?;
        assert_change(base.name, &change, signed, &expected)?;
    }
    Ok(())
}

/// Vector 51's eight root members.
fn v51_roots() -> Result<Vec<[u8; 33]>, Error> {
    V51_KEYS
        .iter()
        .take(8)
        .map(|key| array::<33>(key))
        .collect()
}

/// What spec 25 states about Vector 54 (`label` "cosigns") or Vector 55
/// ("lost"), each a `RootRecovery` on Vector 41.
fn recovery_change(label: &str) -> Result<Expected, Error> {
    let v41_root = array::<33>(V41_ROOT)?;
    let v41_active = array::<33>(V41_ACTIVE)?;
    let k_prime = point(&format!("scp-25-recovery-{label}-root"));
    let active = point(&format!("scp-25-recovery-{label}-active"));
    let mut signers = vec![
        group_of(SignerGroupRole::Reveal, &[array::<33>(V47A_POINT)?])?,
        group_of(SignerGroupRole::ReplacementRoot, &[k_prime])?,
    ];
    if label == "cosigns" {
        signers.push(group_of(SignerGroupRole::StandingRoot, &[v41_root])?);
    }
    Ok(Expected {
        digest_hex: if label == "cosigns" {
            V54_DIGEST
        } else {
            V55_DIGEST
        },
        signers,
        effect: on_v41(
            EventKind::RootRecovery,
            vec![
                current(k_prime, KeyRole::RootMember),
                current(active, KeyRole::Active),
            ],
            vec![
                entry(v41_root, KeyRole::RootMember, KeyCondition::Superseded),
                entry(v41_active, KeyRole::Active, KeyCondition::Superseded),
            ],
            Some(fixes_one(&point(&format!("scp-25-recovery-{label}-next")))),
            root_of(&[k_prime]),
        )?,
    })
}

/// Each spec 25 chain whose last event is a change past the inception,
/// with what spec 25 states about that change.
fn spec_25_changes() -> Result<Vec<(Base, Expected)>, Error> {
    let v41_root = array::<33>(V41_ROOT)?;
    let v41_active = array::<33>(V41_ACTIVE)?;
    let tertiary = array::<33>(V47A_POINT)?;
    let root = group_of(SignerGroupRole::Root, &[v41_root])?;
    let reveal = group_of(SignerGroupRole::Reveal, &[tertiary])?;
    let standing = group_of(SignerGroupRole::StandingRoot, &[v41_root])?;
    let v51_roots = v51_roots()?;
    let v51_witnesses = vec![identifier(V51_WITNESS)?];
    Ok(vec![
        (
            v41_v50()?,
            Expected {
                digest_hex: V50_DIGEST,
                signers: vec![root.clone()],
                effect: on_v41(
                    EventKind::KeyState,
                    vec![],
                    vec![],
                    None,
                    root_of(&[v41_root]),
                )?,
            },
        ),
        (
            v41_v53()?,
            Expected {
                digest_hex: V53_DIGEST,
                signers: vec![reveal.clone(), standing.clone()],
                effect: on_v41(
                    EventKind::CommitmentRollover,
                    vec![],
                    vec![],
                    Some(fixes_one(&point("scp-25-rollover-next"))),
                    root_of(&[v41_root]),
                )?,
            },
        ),
        (v41_v54()?, recovery_change("cosigns")?),
        (v41_v55()?, recovery_change("lost")?),
        (
            v41_v68()?,
            Expected {
                digest_hex: V68_DIGEST,
                signers: vec![reveal, standing],
                effect: on_v41(
                    EventKind::CommitmentRollover,
                    vec![],
                    vec![],
                    Some(Continuation::Abandons),
                    root_of(&[v41_root]),
                )?,
            },
        ),
        (
            v41_v69()?,
            Expected {
                digest_hex: V69_DIGEST,
                signers: vec![root],
                effect: on_v41(
                    EventKind::KeyState,
                    vec![current(array(V69_ACTIVE)?, KeyRole::Active)],
                    vec![KeyEntry {
                        compromised_from: 1,
                        ..entry(v41_active, KeyRole::Active, KeyCondition::Compromised)
                    }],
                    None,
                    root_of(&[v41_root]),
                )?,
            },
        ),
        (
            v51_chain()?,
            Expected {
                digest_hex: V51_DIGEST,
                signers: vec![group_of(SignerGroupRole::Root, &v51_roots)?],
                effect: ChangeEffect {
                    kind: EventKind::KeyState,
                    sequence: 1,
                    installed_keys: vec![],
                    dropped_keys: vec![],
                    continuation: None,
                    root_before: Some(root_of(&v51_roots)),
                    root_after: root_of(&v51_roots),
                    witnesses_before: Some(v51_witnesses.clone()),
                    witnesses_after: v51_witnesses,
                },
            },
        ),
    ])
}

/// `validate_inception` on the V42 and V51 inceptions reports the digest,
/// the challenge, the root group's key set and the effect the vectors
/// state.
#[test]
fn every_spec_25_inception_reports_what_the_vector_states() -> TestResult {
    let v41_root = array::<33>(V41_ROOT)?;
    let v41_active = array::<33>(V41_ACTIVE)?;
    let tertiary = array::<33>(V47A_POINT)?;
    let v51_roots = v51_roots()?;
    let v51_custody = [
        CustodyType::Passkey,
        CustodyType::Fido2Token,
        CustodyType::Hsm,
        CustodyType::SecureEnclave,
        CustodyType::AndroidKeystore,
        CustodyType::EncryptedOfflineBackup,
        CustodyType::ShamirShares,
        CustodyType::PaperBackup,
        CustodyType::Software,
    ];
    let v51_installed = V51_KEYS
        .iter()
        .zip(v51_custody)
        .enumerate()
        .map(|(index, (key, custody_type))| {
            let role = if index < 8 {
                KeyRole::RootMember
            } else {
                KeyRole::Active
            };
            Ok(KeyEntry {
                custody_type,
                ..current(array(key)?, role)
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let inceptions = [
        (
            "V42",
            v42()?.units.first().ok_or("no V42")?.clone(),
            Expected {
                digest_hex: V42_DIGEST,
                signers: vec![group_of(SignerGroupRole::Root, &[v41_root])?],
                effect: ChangeEffect {
                    kind: EventKind::Inception,
                    sequence: 0,
                    installed_keys: vec![
                        current(v41_root, KeyRole::RootMember),
                        current(v41_active, KeyRole::Active),
                    ],
                    dropped_keys: vec![],
                    continuation: Some(fixes_one(&tertiary)),
                    root_before: None,
                    root_after: root_of(&[v41_root]),
                    witnesses_before: None,
                    witnesses_after: vec![identifier(V41_WITNESS)?],
                },
            },
        ),
        (
            "V51i",
            v51_chain()?
                .units
                .first()
                .ok_or("no V51 inception")?
                .clone(),
            Expected {
                digest_hex: V51_INCEPTION_DIGEST,
                signers: vec![group_of(SignerGroupRole::Root, &v51_roots)?],
                effect: ChangeEffect {
                    kind: EventKind::Inception,
                    sequence: 0,
                    installed_keys: v51_installed,
                    dropped_keys: vec![],
                    continuation: Some(fixes_one(&array(V51_PREROTATION)?)),
                    root_before: None,
                    root_after: root_of(&v51_roots),
                    witnesses_before: None,
                    witnesses_after: vec![identifier(V51_WITNESS)?],
                },
            },
        ),
    ];
    for (name, unit, expected) in inceptions {
        let signed = signed_of(&unit)?;
        let change =
            validate_inception(signed).map_err(|refusal| format!("{name}: {refusal:?}"))?;
        assert_change(name, &change, signed, &expected)?;
    }
    Ok(())
}

/// A change no spec 25 vector makes: a `KeyState` on F3's 2-of-3 root,
/// signed by two members, that replaces the witness set. R10 reports the
/// group's threshold and both named indices, and the witnesses before and
/// after.
#[test]
fn a_two_of_three_witness_change_reports_its_signers_and_witnesses() -> TestResult {
    let ring = Ring::new()?;
    let base = f3(&ring)?;
    let before = f3_inception()?.key_state.ok_or("F3 carries a snapshot")?;
    let mut after = before.clone();
    after.witnesses = vec![Identifier::from_bytes([0x77; 32])];
    let mut preimage = key_state_on(&base, after.clone());
    preimage.signer_groups = vec![group(&[0, 1])];
    let unit = sign_on(&ring, &base, &preimage)?;
    let (chain, discarded) = valid(&base.identifier, &base.with(&unit))?;
    assert!(discarded.is_empty(), "{discarded:?}");
    assert_eq!(chain.head_digest(), digest_of(signed_of(&unit)?));
    let change = chain_of(&base)?
        .validate_change(signed_of(&unit)?)
        .map_err(|discard| format!("{discard:?}"))?;
    let members = [
        point("pr3-f3-root-a"),
        point("pr3-f3-root-b"),
        point("pr3-f3-root-c"),
    ];
    let mut signers = group_of(SignerGroupRole::Root, &members)?;
    signers.threshold = 2;
    signers.indices = vec![0, 1];
    assert_eq!(change.signers(), [signers].as_slice());
    let effect = change.effect();
    assert_eq!(effect.witnesses_before, Some(before.witnesses));
    assert_eq!(effect.witnesses_after, after.witnesses);
    Ok(())
}
