//! Known-answer tests against spec 25 §25.26, §25.28 and §25.29. Each
//! expected value is a spec 25 constant from `fixtures`; each test names its
//! vector.

use scp_kel::{
    DeriveIdentifierError, EventKind, EventPreimage, RoutingKind, SignatureForm, decode_preimage,
    derive_identifier, encode_preimage, event_digest, key_event_seal, prerotation_commitment,
    routing_id, signed_preimage,
};

use crate::fixtures::{
    TestResult, V41_DIGEST, V41_IDENTIFIER, V41_PREIMAGE, V41_ROUTING_DID, V41_ROUTING_SVC,
    V41_ROUTING_WCF, V41_ROUTING_WIT, V42_DIGEST, V42_IDENTIFIER, V42_PREIMAGE, V47A_COMMITMENT,
    V47A_POINT, V47B_COMMITMENT, V47B_POINT, V48_ADDRESS, V48_IDENTIFIER, V50_DIGEST, V50_PREIMAGE,
    V50_SEAL, V50_SEALED_DIGEST, V51_DIGEST, V51_IDENTIFIER, V51_INCEPTION_DIGEST, V51_PREIMAGE,
    V51_ROUTING_DID, array, bytes, fields, identifier, v41_inception, v50_key_state, v51_inception,
    v51_key_state,
};

/// Asserts a preimage's signed bytes, field bytes and digest against a spec
/// 25 vector, and that the field bytes decode back to the preimage.
fn assert_vector(preimage: &EventPreimage, printed_hex: &str, digest_hex: &str) -> TestResult {
    let printed = bytes(printed_hex)?;
    assert_eq!(signed_preimage(preimage)?, printed);
    let field_bytes = fields(printed_hex)?;
    assert_eq!(encode_preimage(preimage)?, field_bytes);
    assert_eq!(event_digest(preimage)?, array::<32>(digest_hex)?);
    assert_eq!(&decode_preimage(&field_bytes)?, preimage);
    Ok(())
}

#[test]
fn vector_41_preimage_digest_and_identifier() -> TestResult {
    let preimage = v41_inception(SignatureForm::Raw)?;
    assert_eq!(bytes(V41_PREIMAGE)?.len(), 364);
    assert_vector(&preimage, V41_PREIMAGE, V41_DIGEST)?;
    assert_eq!(derive_identifier(&preimage)?, identifier(V41_IDENTIFIER)?);
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
fn vector_51_rebuilt_inception_digest_and_identifier() -> TestResult {
    let inception = v51_inception()?;
    assert_eq!(
        event_digest(&inception)?,
        array::<32>(V51_INCEPTION_DIGEST)?
    );
    assert_eq!(derive_identifier(&inception)?, identifier(V51_IDENTIFIER)?);
    let encoded = encode_preimage(&inception)?;
    assert_eq!(decode_preimage(&encoded)?, inception);
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
