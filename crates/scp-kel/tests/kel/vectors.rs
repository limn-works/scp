//! Known-answer tests against spec 25 §25.26, §25.28 and §25.29. Each
//! expected value is a spec 25 constant from `fixtures`, and each test names
//! its vector.

use scp_did::{
    CommitmentEntry, CustodyType, FixedCommitment, Identifier, KeyAlgorithm, KeyCondition,
    KeyEntry, KeyRole, KeyState, StandingCommitment,
};
use scp_kel::{
    DeriveIdentifierError, EventKind, InstalledRootSet, RoutingKind, SignatureForm,
    decode_preimage, derive_identifier, encode_preimage, key_event_seal, prerotation_commitment,
    replay, routing_id,
};

use crate::fixtures::{
    TestResult, V41_ACTIVE, V41_DIGEST, V41_IDENTIFIER, V41_PREIMAGE, V41_ROOT, V41_ROUTING_DID,
    V41_ROUTING_SVC, V41_ROUTING_WCF, V41_ROUTING_WIT, V41_WITNESS, V42_DIGEST, V42_IDENTIFIER,
    V42_PREIMAGE, V47A_COMMITMENT, V47A_POINT, V47B_COMMITMENT, V47B_POINT, V48_ADDRESS,
    V48_IDENTIFIER, V50_DIGEST, V50_PREIMAGE, V50_SEAL, V50_SEALED_DIGEST, V51_DIGEST,
    V51_IDENTIFIER, V51_INCEPTION_DIGEST, V51_INCEPTION_PREIMAGE, V51_INCEPTION_SIGNATURE,
    V51_KEYS, V51_PREIMAGE, V51_ROUTING_DID, V68_DIGEST, V68_PREIMAGE, V68_REVEAL_SIGNATURE,
    V68_ROOT_SIGNATURE, V69_DIGEST, V69_PREIMAGE, V69_ROOT_SIGNATURE, array, assert_signature,
    assert_vector, bytes, fields, identifier, v41_inception, v50_key_state, v51_inception,
    v51_key_state, v68_rollover, v69_key_state,
};

#[test]
fn vector_41_preimage_digest_and_identifier() -> TestResult {
    let preimage = v41_inception(SignatureForm::Raw)?;
    assert_eq!(bytes(V41_PREIMAGE)?.len(), 364);
    assert_vector(&preimage, V41_PREIMAGE, V41_DIGEST)?;
    assert_eq!(derive_identifier(&preimage)?, identifier(V41_IDENTIFIER)?);
    // The bytes a verifier received derive the same identifier with no
    // re-encode.
    assert_eq!(
        decode_preimage(&fields(V41_PREIMAGE)?)?.inception_identifier(),
        Some(identifier(V41_IDENTIFIER)?)
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
    // A non-inception event derives no identifier: its field 2 is the
    // identifier it claims, which only the preimage's field reports.
    let encoded = encode_preimage(&preimage)?;
    assert_eq!(encoded.inception_identifier(), None);
    assert_eq!(encoded.preimage().identifier, identifier(V41_IDENTIFIER)?);
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
/// component of the key state except the standing commitment"), read
/// through `replay` over the validated [Vector 41].
#[test]
fn vector_41_snapshot_composes_its_key_state() -> TestResult {
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
        standing_commitment: StandingCommitment::Fixed(FixedCommitment {
            commitments: vec![CommitmentEntry {
                commitment: array(V47A_COMMITMENT)?,
                custody_type: CustodyType::Passkey,
                key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
            }],
            next_threshold: 1,
        }),
    };
    assert_eq!(
        replay(&super::chain_valid::chain_of(&super::chain_support::v41()?)?).key_state(),
        &expected
    );
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
