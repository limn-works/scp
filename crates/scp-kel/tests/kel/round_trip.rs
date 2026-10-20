//! Every encodable preimage of all four kinds decodes back to itself, and its
//! signed preimage is the event separator followed by its field bytes
//! (`09-security-model.md` §9.7.4.2).

use proptest::collection::vec;
use proptest::prelude::*;
use scp_did::{
    CommitmentEntry, CustodyType, Identifier, KeyAlgorithm, KeyCondition, KeyEntry, KeyRole,
    StandingCommitment,
};
use scp_kel::constants::KEL_EVENT_SEPARATOR;
use scp_kel::{
    CommitmentRolloverFields, Continuation, EventPreimage, InceptionFields, InstalledRootSet,
    KeyStateFields, KeyStateSnapshot, RootRecoveryFields, RootRecoveryStanding, SignatureForm,
    SignerGroup, decode_preimage, encode_preimage, signed_preimage,
};

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

fn group() -> impl Strategy<Value = SignerGroup> {
    (
        vec(any::<u8>(), 0..=16),
        vec(
            prop_oneof![
                Just(SignatureForm::Raw),
                Just(SignatureForm::WebAuthnAssertion)
            ],
            0..=16,
        ),
    )
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

fn snapshot() -> impl Strategy<Value = KeyStateSnapshot> {
    (
        1..=u32::MAX,
        vec(key_entry(), 0..6),
        vec(identifier(), 0..=4),
        any::<u32>(),
        role(),
        identifier(),
    )
        .prop_map(
            |(
                root_threshold,
                keys,
                witnesses,
                witnessing_interval,
                service_key_role,
                delegator,
            )| {
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

fn root_set() -> impl Strategy<Value = InstalledRootSet> {
    (vec(point(), 1..=16), any::<u32>())
        .prop_map(|(members, threshold)| InstalledRootSet { members, threshold })
}

fn continuation() -> impl Strategy<Value = Continuation> {
    let commitment =
        (any::<[u8; 32]>(), custody()).prop_map(|(commitment, custody_type)| CommitmentEntry {
            commitment,
            custody_type,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        });
    prop_oneof![
        Just(Continuation::Abandons),
        (vec(commitment, 0..=16), any::<u32>()).prop_map(|(commitments, next_threshold)| {
            Continuation::FixesCommitment(StandingCommitment {
                commitments,
                next_threshold,
            })
        }),
    ]
}

fn inception() -> impl Strategy<Value = EventPreimage> {
    (group(), root_set(), snapshot(), continuation()).prop_map(
        |(root_group, installed_root_set, key_state, continuation)| {
            EventPreimage::inception(InceptionFields {
                root_group,
                installed_root_set,
                key_state,
                continuation,
            })
        },
    )
}

fn key_state() -> impl Strategy<Value = EventPreimage> {
    (
        identifier(),
        any::<u64>(),
        any::<[u8; 32]>(),
        group(),
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
        group(),
        group(),
        vec(point(), 0..=16),
        continuation(),
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
        Just(RootRecoveryStanding::Lost),
        group().prop_map(|standing_root_group| RootRecoveryStanding::CoSigns {
            standing_root_group
        }),
    ];
    (
        (identifier(), any::<u64>(), any::<[u8; 32]>(), standing),
        (group(), group(), vec(point(), 0..=16)),
        (root_set(), snapshot(), continuation()),
    )
        .prop_map(
            |(
                (identifier, sequence, predecessor_digest, standing_root),
                (reveal_group, replacement_root_group, revealed_keys),
                (installed_root_set, key_state, continuation),
            )| {
                EventPreimage::root_recovery(RootRecoveryFields {
                    identifier,
                    sequence,
                    predecessor_digest,
                    standing_root,
                    reveal_group,
                    replacement_root_group,
                    revealed_keys,
                    installed_root_set,
                    key_state,
                    continuation,
                })
            },
        )
}

fn any_preimage() -> impl Strategy<Value = EventPreimage> {
    prop_oneof![
        inception(),
        key_state(),
        commitment_rollover(),
        root_recovery()
    ]
}

proptest! {
    #[test]
    fn every_encodable_preimage_decodes_to_itself(preimage in any_preimage()) {
        let field_bytes = encode_preimage(&preimage)?;
        prop_assert_eq!(&decode_preimage(&field_bytes)?, &preimage);
        let signed = signed_preimage(&preimage)?;
        prop_assert_eq!(signed.get(..KEL_EVENT_SEPARATOR.len()), Some(KEL_EVENT_SEPARATOR));
        prop_assert_eq!(signed.get(KEL_EVENT_SEPARATOR.len()..), Some(&field_bytes[..]));
    }
}
