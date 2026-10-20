//! Known-answer tests against spec 25 §25.26, §25.28 and §25.29. Each
//! expected value is a spec 25 constant, from `fixtures` or, for Vectors 68
//! and 69 and Vector 51's inception signature, from this module; each test
//! names its vector.

use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
use scp_did::{
    CommitmentEntry, CustodyType, Identifier, KeyAlgorithm, KeyCondition, KeyEntry, KeyRole,
    KeyState, StandingCommitment,
};
use scp_kel::{
    CommitmentRolloverFields, Continuation, DeriveIdentifierError, EventKind, EventPreimage,
    InstalledRootSet, KeyStateFields, KeyStateSnapshot, RoutingKind, SignatureForm, SignerGroup,
    decode_preimage, derive_identifier, encode_preimage, key_event_seal, prerotation_commitment,
    routing_id,
};

use crate::fixtures::{
    TestResult, V41_ACTIVE, V41_DIGEST, V41_IDENTIFIER, V41_PREIMAGE, V41_ROOT, V41_ROUTING_DID,
    V41_ROUTING_SVC, V41_ROUTING_WCF, V41_ROUTING_WIT, V41_WITNESS, V42_DIGEST, V42_IDENTIFIER,
    V42_PREIMAGE, V47A_COMMITMENT, V47A_POINT, V47B_COMMITMENT, V47B_POINT, V48_ADDRESS,
    V48_IDENTIFIER, V50_DIGEST, V50_PREIMAGE, V50_SEAL, V50_SEALED_DIGEST, V51_DIGEST,
    V51_IDENTIFIER, V51_INCEPTION_DIGEST, V51_INCEPTION_PREIMAGE, V51_KEYS, V51_PREIMAGE,
    V51_ROUTING_DID, array, assert_vector, bytes, fields, identifier, v41_inception, v50_key_state,
    v51_inception, v51_key_state,
};

/// Spec 25 Vector 51's inception signature: root member 0, raw form, over
/// the inception digest.
const V51_INCEPTION_SIGNATURE: &str = concat!(
    "d7104ac11c070044300192427fa05d9ed127ae5d9544067240e3216da92145f3",
    "4c408c2b1ebdbe3db03f6c81700003f24f3a474ea18352af47a12b461fe6fcf6",
);

/// Spec 25 Vector 68's preimage (161 bytes): Vector 53's rollover with
/// field 12 the one byte `0x00`.
const V68_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a032c0f7f4478be94db0078311ef51b",
    "a3cc9934362b0f154dcbf9c597572e46cf320000000000000001d8ba4ebad526",
    "57208736f4cac675352f5f9cc0aa837620f8d742dbf42aeedbd7000000000100",
    "00000001000000000101000000010100000001026fc6523b7b1e22ff3fbce874",
    "0cfbb7cbc816501864bf40f683db69c860d1a670000000000000000000000000",
    "00",
);
/// Spec 25 Vector 68's preimage digest.
const V68_DIGEST: &str = "9c6a3dcdcff0e73c03859c375debc8ec3e3c70c5834fd111b9f94e055a28b22e";
/// Spec 25 Vector 68's reveal signature, by the revealed key.
const V68_REVEAL_SIGNATURE: &str = concat!(
    "87c8850628e69a3e77bf240285c240fd6a38c0149091f380a447c51b2d8da510",
    "058f10913c5fa2f6abe1345defd0ba55627a1b447f05f22e89f4a9e7233ccf61",
);
/// Spec 25 Vector 68's standing-root signature, by Vector 41's root member 0.
const V68_ROOT_SIGNATURE: &str = concat!(
    "c5f3d73bf438c4f3503a1b33c239934d62819ac8d319079b466b02892b273cf6",
    "3ee408b9f697d1c5ebac883cde74139dfda09c4fcba7800415bc110bcb57e8dd",
);

/// Spec 25 Vector 69's preimage (333 bytes).
const V69_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a022c0f7f4478be94db0078311ef51b",
    "a3cc9934362b0f154dcbf9c597572e46cf320000000000000001d8ba4ebad526",
    "57208736f4cac675352f5f9cc0aa837620f8d742dbf42aeedbd7000000000100",
    "000000010100000000000000000000000100000003033b1cac23f45cf1cdfdf0",
    "b32f8f777b99166c1b69649c2295b1517883d47f302701010000000000000000",
    "010103111dadf2081befb113b3e43ce763df7d1c34b64f01778fb108087894ac",
    "ae761c0201000000000000000001010223702a648232f2d00713de9289753c2f",
    "bd4c4efa7e1e33905e3723a412b20aea02040000000000000001010100000001",
    "9d94df95bc0a13f1963f484414c320354c73c75bb86e96559e97765f5bc2d313",
    "00000e1002000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000",
);
/// Spec 25 Vector 69's preimage digest.
const V69_DIGEST: &str = "12f301331515b7108969e5649b025e98847a14d290fe9ee093dfecc9a5355168";
/// Spec 25 Vector 69's installed `#active` key.
const V69_ACTIVE: &str = "03111dadf2081befb113b3e43ce763df7d1c34b64f01778fb108087894acae761c";
/// Spec 25 Vector 69's root signature, by Vector 41's root member 0.
const V69_ROOT_SIGNATURE: &str = concat!(
    "b622e40aa201d477309172165de6cc4fa7ae83f72efc349152e5e5d82d5bf32c",
    "0ea4c8119dc25851f952fbd9f8e5607a8b021a4061fbb0219bb70efa3f35d81c",
);

/// Verifies a spec 25 raw-form indexed signature with the §9.5.1 strict
/// verifier.
fn assert_signature(key_hex: &str, digest_hex: &str, signature_hex: &str) -> TestResult {
    let key = P256PublicKey::from_sec1(&bytes(key_hex)?)?;
    verify_prehash_strict(&key, &array(digest_hex)?, &bytes(signature_hex)?)?;
    Ok(())
}

fn raw_group() -> SignerGroup {
    SignerGroup {
        indices: vec![0],
        forms: vec![SignatureForm::Raw],
    }
}

const fn passkey_entry(
    key: [u8; 33],
    role: KeyRole,
    condition: KeyCondition,
    compromised_from: u64,
) -> KeyEntry {
    KeyEntry {
        key,
        role,
        condition,
        compromised_from,
        custody_type: CustodyType::Passkey,
        key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
    }
}

/// Vector 68: an abandoning `CommitmentRollover` at sequence 1 over Vector 41.
fn v68_rollover() -> Result<EventPreimage, Box<dyn std::error::Error>> {
    Ok(EventPreimage::commitment_rollover(
        CommitmentRolloverFields {
            identifier: identifier(V41_IDENTIFIER)?,
            sequence: 1,
            predecessor_digest: array(V41_DIGEST)?,
            reveal_group: raw_group(),
            standing_root_group: raw_group(),
            revealed_keys: vec![array(V47A_POINT)?],
            continuation: Continuation::Abandons,
        },
    ))
}

/// Vector 69: a `KeyState` at sequence 1 over Vector 41 that keeps the root,
/// installs a new `#active` key, and drops Vector 41's `#active` key as
/// `Compromised{from: 1}`.
fn v69_key_state() -> Result<EventPreimage, Box<dyn std::error::Error>> {
    Ok(EventPreimage::key_state(KeyStateFields {
        identifier: identifier(V41_IDENTIFIER)?,
        sequence: 1,
        predecessor_digest: array(V41_DIGEST)?,
        root_group: raw_group(),
        key_state: KeyStateSnapshot {
            root_threshold: 1,
            keys: vec![
                passkey_entry(
                    array(V41_ROOT)?,
                    KeyRole::RootMember,
                    KeyCondition::Current,
                    0,
                ),
                passkey_entry(
                    array(V69_ACTIVE)?,
                    KeyRole::Active,
                    KeyCondition::Current,
                    0,
                ),
                passkey_entry(
                    array(V41_ACTIVE)?,
                    KeyRole::Active,
                    KeyCondition::Compromised,
                    1,
                ),
            ],
            witnesses: vec![identifier(V41_WITNESS)?],
            witnessing_interval: 3600,
            service_key_role: KeyRole::Active,
            delegator: Identifier::ZERO,
        },
        seals: Vec::new(),
    }))
}

#[test]
fn vector_41_preimage_digest_and_identifier() -> TestResult {
    let preimage = v41_inception(SignatureForm::Raw)?;
    assert_eq!(bytes(V41_PREIMAGE)?.len(), 364);
    assert_vector(&preimage, V41_PREIMAGE, V41_DIGEST)?;
    assert_eq!(derive_identifier(&preimage)?, identifier(V41_IDENTIFIER)?);
    // The bytes a verifier received derive the same identifier with no
    // re-encode.
    assert_eq!(
        decode_preimage(&fields(V41_PREIMAGE)?)?.identifier(),
        identifier(V41_IDENTIFIER)?
    );
    Ok(())
}

#[test]
fn vector_42_preimage_digest_and_identifier() -> TestResult {
    let preimage = v41_inception(SignatureForm::WebAuthnAssertion)?;
    assert_vector(&preimage, V42_PREIMAGE, V42_DIGEST)?;
    assert_eq!(derive_identifier(&preimage)?, identifier(V42_IDENTIFIER)?);
    Ok(())
}

#[test]
fn vector_50_key_state_pins_both_composite_sentinels() -> TestResult {
    let preimage = v50_key_state()?;
    assert_eq!(bytes(V50_PREIMAGE)?.len(), 320);
    assert_vector(&preimage, V50_PREIMAGE, V50_DIGEST)?;
    // The last four bytes are field 12's sentinel, never the one byte 0x00.
    assert_eq!(bytes(V50_PREIMAGE)?.get(316..), Some(&[0u8; 4][..]));
    // A non-inception event's identifier is the field 2 identifier it carries.
    assert_eq!(
        encode_preimage(&preimage)?.identifier(),
        identifier(V41_IDENTIFIER)?
    );
    Ok(())
}

#[test]
fn vector_50_key_event_seal() -> TestResult {
    assert_eq!(
        key_event_seal(&array(V50_SEALED_DIGEST)?),
        array::<32>(V50_SEAL)?
    );
    Ok(())
}

#[test]
fn vector_51_key_state_carries_every_custody_type() -> TestResult {
    let preimage = v51_key_state()?;
    assert_eq!(bytes(V51_PREIMAGE)?.len(), 603);
    assert_vector(&preimage, V51_PREIMAGE, V51_DIGEST)
}

#[test]
fn vector_51_inception_preimage_digest_and_identifier() -> TestResult {
    let inception = v51_inception()?;
    assert_eq!(bytes(V51_INCEPTION_PREIMAGE)?.len(), 910);
    assert_vector(&inception, V51_INCEPTION_PREIMAGE, V51_INCEPTION_DIGEST)?;
    assert_eq!(derive_identifier(&inception)?, identifier(V51_IDENTIFIER)?);
    // Field 9 is the snapshot's eight root members, installed 1-of-8.
    let mut members = Vec::new();
    for key in V51_KEYS.iter().take(8) {
        members.push(array(key)?);
    }
    assert_eq!(
        inception.installed_root_set,
        Some(InstalledRootSet {
            members,
            threshold: 1
        })
    );
    Ok(())
}

#[test]
fn vector_51_inception_signature_verifies_under_root_member_0() -> TestResult {
    assert_signature(V51_KEYS[0], V51_INCEPTION_DIGEST, V51_INCEPTION_SIGNATURE)
}

#[test]
fn vector_68_abandoning_rollover_preimage_digest_and_signatures() -> TestResult {
    let preimage = v68_rollover()?;
    assert_eq!(bytes(V68_PREIMAGE)?.len(), 161);
    assert_vector(&preimage, V68_PREIMAGE, V68_DIGEST)?;
    // Field 12 is the one byte 0x00, the registered abandonment value, and
    // nothing follows it.
    assert_eq!(bytes(V68_PREIMAGE)?.last(), Some(&0x00));
    // The reveal group verifies against the revealed key and the
    // standing-root group against Vector 41's root member 0.
    assert_signature(V47A_POINT, V68_DIGEST, V68_REVEAL_SIGNATURE)?;
    assert_signature(V41_ROOT, V68_DIGEST, V68_ROOT_SIGNATURE)
}

#[test]
fn vector_69_compromised_key_state_preimage_digest_and_signature() -> TestResult {
    let preimage = v69_key_state()?;
    assert_eq!(bytes(V69_PREIMAGE)?.len(), 333);
    assert_vector(&preimage, V69_PREIMAGE, V69_DIGEST)?;
    let snapshot = decode_preimage(&fields(V69_PREIMAGE)?)?
        .into_preimage()
        .key_state
        .ok_or("Vector 69 carries a snapshot")?;
    let dropped = snapshot.keys.get(2).ok_or("Vector 69 lists three keys")?;
    assert_eq!(dropped.key, array::<33>(V41_ACTIVE)?);
    assert_eq!(dropped.condition, KeyCondition::Compromised);
    assert_eq!(dropped.compromised_from, 1);
    assert_signature(V41_ROOT, V69_DIGEST, V69_ROOT_SIGNATURE)
}

/// The V41 inception's snapshot and its continuation's commitment compose the
/// key state that inception installs (§9.7.4.2: "A snapshot carries every
/// component of the key state except the standing commitment").
#[test]
fn vector_41_snapshot_composes_its_key_state() -> TestResult {
    let decoded = decode_preimage(&fields(V41_PREIMAGE)?)?.into_preimage();
    let snapshot = decoded.key_state.ok_or("V41 carries a snapshot")?;
    let Some(Continuation::FixesCommitment(commitment)) = decoded.continuation else {
        return Err("V41 fixes a commitment".into());
    };
    let entry = |key, role| -> Result<KeyEntry, Box<dyn std::error::Error>> {
        Ok(KeyEntry {
            key: array(key)?,
            role,
            condition: KeyCondition::Current,
            compromised_from: 0,
            custody_type: CustodyType::Passkey,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        })
    };
    let expected = KeyState {
        root_threshold: 1,
        keys: vec![
            entry(V41_ROOT, KeyRole::RootMember)?,
            entry(V41_ACTIVE, KeyRole::Active)?,
        ],
        witnesses: vec![identifier(V41_WITNESS)?],
        witnessing_interval: 3600,
        service_key_role: KeyRole::Active,
        delegator: Identifier::ZERO,
        standing_commitment: StandingCommitment {
            commitments: vec![CommitmentEntry {
                commitment: array(V47A_COMMITMENT)?,
                custody_type: CustodyType::Passkey,
                key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
            }],
            next_threshold: 1,
        },
    };
    assert_eq!(snapshot.into_key_state(commitment), expected);
    Ok(())
}

#[test]
fn vector_41_routing_ids_for_all_four_kinds() -> TestResult {
    let id = identifier(V41_IDENTIFIER)?;
    assert_eq!(
        routing_id(RoutingKind::KeyEvents, &id),
        array::<32>(V41_ROUTING_DID)?
    );
    assert_eq!(
        routing_id(RoutingKind::CosignedHeads, &id),
        array::<32>(V41_ROUTING_WIT)?
    );
    assert_eq!(
        routing_id(RoutingKind::ConflictStatements, &id),
        array::<32>(V41_ROUTING_WCF)?
    );
    assert_eq!(
        routing_id(RoutingKind::ServiceRecord, &id),
        array::<32>(V41_ROUTING_SVC)?
    );
    Ok(())
}

#[test]
fn vector_48_service_record_address() -> TestResult {
    assert_eq!(
        routing_id(RoutingKind::ServiceRecord, &identifier(V48_IDENTIFIER)?),
        array::<32>(V48_ADDRESS)?
    );
    Ok(())
}

#[test]
fn vector_51_routing_id() -> TestResult {
    assert_eq!(
        routing_id(RoutingKind::KeyEvents, &identifier(V51_IDENTIFIER)?),
        array::<32>(V51_ROUTING_DID)?
    );
    Ok(())
}

#[test]
fn vector_47a_prerotation_commitment() -> TestResult {
    assert_eq!(
        prerotation_commitment(&array(V47A_POINT)?),
        array::<32>(V47A_COMMITMENT)?
    );
    Ok(())
}

#[test]
fn vector_47b_prerotation_commitment() -> TestResult {
    assert_eq!(
        prerotation_commitment(&array(V47B_POINT)?),
        array::<32>(V47B_COMMITMENT)?
    );
    Ok(())
}

#[test]
fn derive_identifier_rejects_a_non_inception_kind() -> TestResult {
    // Vector 50 is a KeyState.
    assert_eq!(
        derive_identifier(&v50_key_state()?),
        Err(DeriveIdentifierError::NotInception {
            kind: EventKind::KeyState
        })
    );
    Ok(())
}

#[test]
fn derive_identifier_rejects_a_nonzero_identifier() -> TestResult {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    preimage.identifier = identifier(V41_IDENTIFIER)?;
    assert_eq!(
        derive_identifier(&preimage),
        Err(DeriveIdentifierError::NonzeroIdentifier)
    );
    Ok(())
}

#[test]
fn derive_identifier_rejects_a_nonzero_sequence() -> TestResult {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    preimage.sequence = 1;
    assert_eq!(
        derive_identifier(&preimage),
        Err(DeriveIdentifierError::NonzeroSequence { sequence: 1 })
    );
    Ok(())
}

#[test]
fn derive_identifier_rejects_a_nonzero_predecessor() -> TestResult {
    let mut preimage = v41_inception(SignatureForm::Raw)?;
    preimage.predecessor_digest[31] = 1;
    assert_eq!(
        derive_identifier(&preimage),
        Err(DeriveIdentifierError::NonzeroPredecessor)
    );
    Ok(())
}
