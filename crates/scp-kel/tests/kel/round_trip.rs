//! The codec's identities (`09-security-model.md` §9.7.4.2):
//!
//! - every preimage the constructors build decodes back to itself, and its
//!   signed preimage is the event separator followed by its field bytes;
//! - over arbitrary preimages, lists past every §9.18.17 maximum and field
//!   bytes past `MAX_EVENT_BYTES` included, encode succeeds exactly where
//!   decode of its output succeeds, and decode returns the preimage;
//! - every mutation of a spec 25 vector's field bytes that decodes
//!   re-encodes to the identical bytes, so no event has a second encoding.

use proptest::collection::vec;
use proptest::prelude::*;
use scp_did::{
    CommitmentEntry, CustodyType, FixedCommitment, Identifier, KeyAlgorithm, KeyCondition,
    KeyEntry, KeyRole,
};
use scp_kel::{
    CommitmentRolloverFields, Continuation, EventKind, EventPreimage, InceptionFields,
    InstalledRootSet, KeyStateFields, KeyStateSnapshot, RootRecoveryFields, SignatureForm,
    SignerGroup, StandingRootDeclaration, StandingRootSigning, decode_preimage, encode_preimage,
    signer_group_roles,
};

use crate::fixtures::{
    V41_PREIMAGE, V42_PREIMAGE, V50_PREIMAGE, V51_INCEPTION_PREIMAGE, V51_PREIMAGE, fields,
};

/// §9.7.4.2 R13's event separator, written out: the crate keeps its own
/// copy private.
const EVENT_SEPARATOR: &[u8] = b"SCP-KEL-EVENT-V1:";

const CUSTODY: [CustodyType; 9] = [
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

fn point() -> impl Strategy<Value = [u8; 33]> {
    (any::<[u8; 32]>(), prop_oneof![Just(2u8), Just(3u8)]).prop_map(|(x, prefix)| {
        let mut point = [prefix; 33];
        point[1..].copy_from_slice(&x);
        point
    })
}

fn identifier() -> impl Strategy<Value = Identifier> {
    any::<[u8; 32]>().prop_map(Identifier::from_bytes)
}

fn custody() -> impl Strategy<Value = CustodyType> {
    proptest::sample::select(CUSTODY.to_vec())
}

fn role() -> impl Strategy<Value = KeyRole> {
    prop_oneof![Just(KeyRole::RootMember), Just(KeyRole::Active)]
}

fn form() -> impl Strategy<Value = SignatureForm> {
    prop_oneof![
        Just(SignatureForm::Raw),
        Just(SignatureForm::WebAuthnAssertion)
    ]
}

/// A signer group with `max` indices at most, each with its form.
fn group(max: usize) -> impl Strategy<Value = SignerGroup> {
    vec((any::<u8>(), form()), 0..=max).prop_map(|signers| {
        let (indices, forms) = signers.into_iter().unzip();
        SignerGroup { indices, forms }
    })
}

/// A signer group whose form list's length is drawn apart from its index
/// list's, so it is mostly unpaired.
fn unpaired_group(max: usize) -> impl Strategy<Value = SignerGroup> {
    (vec(any::<u8>(), 0..=max), vec(form(), 0..=max))
        .prop_map(|(indices, forms)| SignerGroup { indices, forms })
}

/// A key entry whose `compromised_from` is nonzero only under `Compromised`.
fn key_entry() -> impl Strategy<Value = KeyEntry> {
    let condition = prop_oneof![
        Just((KeyCondition::Current, 0u64)),
        Just((KeyCondition::Superseded, 0u64)),
        Just((KeyCondition::Retired, 0u64)),
        any::<u64>().prop_map(|position| (KeyCondition::Compromised, position)),
    ];
    (point(), role(), condition, custody()).prop_map(
        |(key, role, (condition, compromised_from), custody_type)| KeyEntry {
            key,
            role,
            condition,
            compromised_from,
            custody_type,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        },
    )
}

/// A key entry with any condition and any `compromised_from`, so the codec's
/// "zero otherwise" rule is reached from both sides.
fn any_key_entry() -> impl Strategy<Value = KeyEntry> {
    let condition = prop_oneof![
        Just(KeyCondition::Current),
        Just(KeyCondition::Superseded),
        Just(KeyCondition::Retired),
        Just(KeyCondition::Compromised),
    ];
    let compromised_from = prop_oneof![3 => Just(0u64), 1 => any::<u64>()];
    (point(), role(), condition, compromised_from, custody()).prop_map(
        |(key, role, condition, compromised_from, custody_type)| KeyEntry {
            key,
            role,
            condition,
            compromised_from,
            custody_type,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        },
    )
}

/// A snapshot whose first key is a `Current` root member, so the root set
/// the constructors derive from it is never empty.
fn snapshot() -> impl Strategy<Value = KeyStateSnapshot> {
    (
        (1..=u32::MAX, point(), custody(), vec(key_entry(), 0..6)),
        (vec(identifier(), 0..=4), any::<u32>(), role(), identifier()),
    )
        .prop_map(
            |(
                (root_threshold, root_key, root_custody, rest),
                (witnesses, witnessing_interval, service_key_role, delegator),
            )| {
                let mut keys = vec![KeyEntry {
                    key: root_key,
                    role: KeyRole::RootMember,
                    condition: KeyCondition::Current,
                    compromised_from: 0,
                    custody_type: root_custody,
                    key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
                }];
                keys.extend(rest);
                KeyStateSnapshot {
                    root_threshold,
                    keys,
                    witnesses,
                    witnessing_interval,
                    service_key_role,
                    delegator,
                }
            },
        )
}

fn commitment_entry() -> impl Strategy<Value = CommitmentEntry> {
    (any::<[u8; 32]>(), custody()).prop_map(|(commitment, custody_type)| CommitmentEntry {
        commitment,
        custody_type,
        key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
    })
}

/// A continuation with `max` commitments at most.
fn continuation(max: usize) -> impl Strategy<Value = Continuation> {
    prop_oneof![
        Just(Continuation::Abandons),
        (vec(commitment_entry(), 0..=max), any::<u32>()).prop_map(
            |(commitments, next_threshold)| {
                Continuation::FixesCommitment(FixedCommitment {
                    commitments,
                    next_threshold,
                })
            }
        ),
    ]
}

fn inception() -> impl Strategy<Value = EventPreimage> {
    (group(16), snapshot(), continuation(16)).prop_map(|(root_group, key_state, continuation)| {
        EventPreimage::inception(InceptionFields {
            root_group,
            key_state,
            continuation,
        })
    })
}

fn key_state() -> impl Strategy<Value = EventPreimage> {
    (
        identifier(),
        any::<u64>(),
        any::<[u8; 32]>(),
        group(16),
        snapshot(),
        vec(any::<[u8; 32]>(), 0..4),
    )
        .prop_map(
            |(identifier, sequence, predecessor_digest, root_group, key_state, seals)| {
                EventPreimage::key_state(KeyStateFields {
                    identifier,
                    sequence,
                    predecessor_digest,
                    root_group,
                    key_state,
                    seals,
                })
            },
        )
}

fn commitment_rollover() -> impl Strategy<Value = EventPreimage> {
    (
        identifier(),
        any::<u64>(),
        any::<[u8; 32]>(),
        group(16),
        group(16),
        vec(point(), 0..=16),
        continuation(16),
    )
        .prop_map(
            |(
                identifier,
                sequence,
                predecessor_digest,
                reveal_group,
                standing_root_group,
                revealed_keys,
                continuation,
            )| {
                EventPreimage::commitment_rollover(CommitmentRolloverFields {
                    identifier,
                    sequence,
                    predecessor_digest,
                    reveal_group,
                    standing_root_group,
                    revealed_keys,
                    continuation,
                })
            },
        )
}

fn root_recovery() -> impl Strategy<Value = EventPreimage> {
    let standing = prop_oneof![
        Just(StandingRootSigning::Lost),
        group(16).prop_map(|standing_root_group| StandingRootSigning::CoSigns {
            standing_root_group
        }),
    ];
    (
        (identifier(), any::<u64>(), any::<[u8; 32]>(), standing),
        (group(16), group(16), vec(point(), 0..=16)),
        (snapshot(), continuation(16)),
    )
        .prop_map(
            |(
                (identifier, sequence, predecessor_digest, standing_root_signing),
                (reveal_group, replacement_root_group, revealed_keys),
                (key_state, continuation),
            )| {
                EventPreimage::root_recovery(RootRecoveryFields {
                    identifier,
                    sequence,
                    predecessor_digest,
                    standing_root_signing,
                    reveal_group,
                    replacement_root_group,
                    revealed_keys,
                    key_state,
                    continuation,
                })
            },
        )
}

fn constructed_preimage() -> impl Strategy<Value = EventPreimage> {
    prop_oneof![
        inception(),
        key_state(),
        commitment_rollover(),
        root_recovery()
    ]
}

// ---------------------------------------------------------------------------
// Arbitrary preimages: every field drawn independently, lists past every
// §9.18.17 maximum (16, 16, 32) and occasionally past MAX_EVENT_BYTES.
// ---------------------------------------------------------------------------

fn kind() -> impl Strategy<Value = EventKind> {
    prop_oneof![
        Just(EventKind::Inception),
        Just(EventKind::KeyState),
        Just(EventKind::CommitmentRollover),
        Just(EventKind::RootRecovery),
    ]
}

fn standing_root() -> impl Strategy<Value = Option<StandingRootDeclaration>> {
    prop_oneof![
        Just(None),
        Just(Some(StandingRootDeclaration::CoSigns)),
        Just(Some(StandingRootDeclaration::Lost)),
    ]
}

/// Mostly the group count the kind names with paired form lists, sometimes
/// unpaired form lists or any count up to four.
fn signer_groups(
    kind: EventKind,
    standing_root: Option<StandingRootDeclaration>,
) -> impl Strategy<Value = Vec<SignerGroup>> {
    let named = signer_group_roles(kind, standing_root).map_or(1, <[_]>::len);
    prop_oneof![
        8 => vec(group(18), named..=named),
        1 => vec(unpaired_group(18), named..=named),
        1 => vec(group(18), 0..=4),
    ]
}

fn arbitrary_snapshot() -> impl Strategy<Value = KeyStateSnapshot> {
    (
        (0..3u32, vec(any_key_entry(), 0..4)),
        (
            vec(identifier(), 0..=34),
            any::<u32>(),
            role(),
            identifier(),
        ),
    )
        .prop_map(
            |(
                (root_threshold, keys),
                (witnesses, witnessing_interval, service_key_role, delegator),
            )| KeyStateSnapshot {
                root_threshold,
                keys,
                witnesses,
                witnessing_interval,
                service_key_role,
                delegator,
            },
        )
}

fn seals() -> impl Strategy<Value = Vec<[u8; 32]>> {
    prop_oneof![
        9 => vec(any::<[u8; 32]>(), 0..4),
        // 2,030 to 2,045 seals straddle MAX_EVENT_BYTES.
        1 => (2030usize..=2045).prop_map(|count| vec![[5; 32]; count]),
    ]
}

fn arbitrary_preimage() -> impl Strategy<Value = EventPreimage> {
    (kind(), standing_root()).prop_flat_map(|(kind, standing_root)| {
        (
            (identifier(), any::<u64>(), any::<[u8; 32]>()),
            signer_groups(kind, standing_root),
            vec(point(), 0..=18),
            proptest::option::of(
                (vec(point(), 0..=18), any::<u32>())
                    .prop_map(|(members, threshold)| InstalledRootSet { members, threshold }),
            ),
            proptest::option::of(arbitrary_snapshot()),
            seals(),
            proptest::option::of(continuation(18)),
        )
            .prop_map(
                move |(
                    (identifier, sequence, predecessor_digest),
                    signer_groups,
                    revealed_keys,
                    installed_root_set,
                    key_state,
                    seals,
                    continuation,
                )| EventPreimage {
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
                },
            )
    })
}

// ---------------------------------------------------------------------------
// Spec 25 vectors, mutated.
// ---------------------------------------------------------------------------

const VECTORS: [&str; 5] = [
    V41_PREIMAGE,
    V42_PREIMAGE,
    V50_PREIMAGE,
    V51_PREIMAGE,
    V51_INCEPTION_PREIMAGE,
];

#[derive(Debug, Clone)]
enum Mutation {
    Overwrite { at: usize, value: u8 },
    Insert { at: usize, value: u8 },
    Delete { at: usize },
    Truncate { at: usize },
    SpliceCount { at: usize, count: u32 },
}

fn mutation() -> impl Strategy<Value = Mutation> {
    let at = any::<usize>();
    let count = prop_oneof![0..=40u32, any::<u32>()];
    prop_oneof![
        4 => (at, any::<u8>()).prop_map(|(at, value)| Mutation::Overwrite { at, value }),
        1 => (at, any::<u8>()).prop_map(|(at, value)| Mutation::Insert { at, value }),
        1 => at.prop_map(|at| Mutation::Delete { at }),
        1 => at.prop_map(|at| Mutation::Truncate { at }),
        3 => (at, count).prop_map(|(at, count)| Mutation::SpliceCount { at, count }),
    ]
}

/// Applies `mutation` to `bytes`, each position taken modulo the length.
fn mutate(mut bytes: Vec<u8>, mutation: &Mutation) -> Vec<u8> {
    let len = bytes.len().max(1);
    match *mutation {
        Mutation::Overwrite { at, value } => {
            if let Some(byte) = bytes.get_mut(at % len) {
                *byte = value;
            }
        }
        Mutation::Insert { at, value } => {
            let at = at % (bytes.len() + 1);
            bytes.insert(at, value);
        }
        Mutation::Delete { at } => {
            if !bytes.is_empty() {
                bytes.remove(at % len);
            }
        }
        Mutation::Truncate { at } => bytes.truncate(at % len),
        Mutation::SpliceCount { at, count } => {
            let at = at % len;
            for (offset, byte) in count.to_be_bytes().into_iter().enumerate() {
                if let Some(slot) = bytes.get_mut(at + offset) {
                    *slot = byte;
                }
            }
        }
    }
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn every_constructed_preimage_decodes_to_itself(preimage in constructed_preimage()) {
        let encoded = encode_preimage(&preimage)?;
        let decoded = decode_preimage(encoded.fields())?;
        prop_assert_eq!(decoded.preimage(), &preimage);
        prop_assert_eq!(&decoded, &encoded);
        let signed = encoded.signed_preimage();
        prop_assert_eq!(signed.get(..EVENT_SEPARATOR.len()), Some(EVENT_SEPARATOR));
        prop_assert_eq!(signed.get(EVENT_SEPARATOR.len()..), Some(encoded.fields()));
    }

    /// Encode succeeds if and only if decode of its output succeeds, and
    /// decode then returns the preimage and the same bytes.
    #[test]
    fn encode_succeeds_iff_its_output_decodes(preimage in arbitrary_preimage()) {
        let encoded = encode_preimage(&preimage);
        let round_trip = encoded
            .clone()
            .map_err(|error| error.to_string())
            .and_then(|encoded| {
                decode_preimage(encoded.fields()).map_err(|error| error.to_string())
            });
        prop_assert_eq!(encoded.is_ok(), round_trip.is_ok(), "{:?} then {:?}", encoded, round_trip);
        if let (Ok(encoded), Ok(decoded)) = (encoded, round_trip) {
            prop_assert_eq!(decoded.preimage(), &preimage);
            prop_assert_eq!(decoded, encoded);
        }
    }

    /// Every mutated spec 25 field byte string the decoder accepts
    /// re-encodes to the identical bytes.
    #[test]
    fn every_accepted_spec_vector_mutation_reencodes_identically(
        vector in 0..VECTORS.len(),
        mutations in vec(mutation(), 1..=3),
    ) {
        let printed = VECTORS.get(vector).ok_or_else(|| TestCaseError::fail("vector"))?;
        let mut bytes = fields(printed).map_err(|error| TestCaseError::fail(error.to_string()))?;
        for mutation in &mutations {
            bytes = mutate(bytes, mutation);
        }
        if let Ok(decoded) = decode_preimage(&bytes) {
            let encoded = encode_preimage(decoded.preimage())?;
            prop_assert_eq!(encoded.fields(), bytes.as_slice());
            prop_assert_eq!(decoded.fields(), bytes.as_slice());
        }
    }
}
