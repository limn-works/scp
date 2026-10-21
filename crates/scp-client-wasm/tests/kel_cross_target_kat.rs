//! Cross-target known-answer tests for the key-event preimage, digest,
//! identifier, seal, commitment and routing ids (`09-security-model.md`
//! §9.7.4.2, R13), the raw-form signatures spec 25 prints for Vectors 51, 68
//! and 69, and the identifier's text form (`03-identity.md` §3.1).
//!
//! The browser client verifies a key event log in wasm32 and a native node
//! verifies the same log, so both must compute the same bytes. Each test
//! runs as a native `#[test]` and as a `#[wasm_bindgen_test]` against the
//! spec 25 constants (§25.26, §25.28, §25.29), so native == spec and
//! wasm32 == spec. The constants and preimage builders are scp-kel's own
//! test fixtures, included by path so one copy of the spec hex serves both
//! crates.

#[path = "../../scp-kel/tests/kel/fixtures.rs"]
mod fixtures;

use fixtures::{
    TestResult, V41_ACTIVE, V41_DIGEST, V41_IDENTIFIER, V41_PREIMAGE, V41_ROOT, V41_ROUTING_DID,
    V41_ROUTING_SVC, V41_ROUTING_WCF, V41_ROUTING_WIT, V42_DIGEST, V42_IDENTIFIER, V42_PREIMAGE,
    V47A_COMMITMENT, V47A_POINT, V47B_COMMITMENT, V47B_POINT, V48_ADDRESS, V48_IDENTIFIER,
    V50_DIGEST, V50_PREIMAGE, V50_SEAL, V50_SEALED_DIGEST, V51_DIGEST, V51_IDENTIFIER,
    V51_INCEPTION_DIGEST, V51_INCEPTION_PREIMAGE, V51_INCEPTION_SIGNATURE, V51_KEYS, V51_PREIMAGE,
    V51_ROUTING_DID, V68_DIGEST, V68_PREIMAGE, V68_REVEAL_SIGNATURE, V68_ROOT_SIGNATURE,
    V69_DIGEST, V69_PREIMAGE, V69_ROOT_SIGNATURE, array, assert_signature, assert_vector, fields,
    identifier, v41_inception, v50_key_state, v51_inception, v51_key_state, v68_rollover,
    v69_key_state,
};
use scp_did::{Identifier, IdentifierError, KeyCondition, NonCanonicalReason};
use scp_kel::{
    RoutingKind, SignatureForm, decode_preimage, derive_identifier, key_event_seal,
    prerotation_commitment, routing_id,
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

/// Vector 57's text form of Vector 41's identifier.
const V57_TEXT: &str = "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za";
/// Vector 57's two rejected variants.
const V57_UPPERCASE: &str = "scp:FQHX6RDYX2KNWADYGEPPKG5DZSMTINRLB4KU3S7ZYWLVOLSGZ4ZA";
const V57_PADDED: &str = "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za====";

/// The identifier text error a non-canonical form returns.
const fn non_canonical(reason: NonCanonicalReason) -> Result<Identifier, IdentifierError> {
    Err(IdentifierError::NonCanonicalIdentifier { reason })
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vector_41_inception() -> TestResult {
    let preimage = v41_inception(SignatureForm::Raw)?;
    assert_vector(&preimage, V41_PREIMAGE, V41_DIGEST)?;
    assert_eq!(derive_identifier(&preimage)?, identifier(V41_IDENTIFIER)?);
    assert_eq!(
        decode_preimage(&fields(V41_PREIMAGE)?)?.identifier(),
        identifier(V41_IDENTIFIER)?
    );
    Ok(())
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vector_42_webauthn_inception() -> TestResult {
    let preimage = v41_inception(SignatureForm::WebAuthnAssertion)?;
    assert_vector(&preimage, V42_PREIMAGE, V42_DIGEST)?;
    assert_eq!(derive_identifier(&preimage)?, identifier(V42_IDENTIFIER)?);
    Ok(())
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vector_50_key_state_and_seal() -> TestResult {
    assert_vector(&v50_key_state()?, V50_PREIMAGE, V50_DIGEST)?;
    assert_eq!(
        key_event_seal(&array(V50_SEALED_DIGEST)?),
        array::<32>(V50_SEAL)?
    );
    Ok(())
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vector_51_inception_and_key_state() -> TestResult {
    let inception = v51_inception()?;
    assert_vector(&inception, V51_INCEPTION_PREIMAGE, V51_INCEPTION_DIGEST)?;
    assert_eq!(derive_identifier(&inception)?, identifier(V51_IDENTIFIER)?);
    assert_vector(&v51_key_state()?, V51_PREIMAGE, V51_DIGEST)?;
    assert_eq!(
        routing_id(RoutingKind::KeyEvents, &identifier(V51_IDENTIFIER)?),
        array::<32>(V51_ROUTING_DID)?
    );
    Ok(())
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vector_51_inception_signature() -> TestResult {
    let root_member_0 = V51_KEYS.first().ok_or("Vector 51 lists root member 0")?;
    assert_signature(root_member_0, V51_INCEPTION_DIGEST, V51_INCEPTION_SIGNATURE)
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vector_68_abandoning_rollover() -> TestResult {
    assert_vector(&v68_rollover()?, V68_PREIMAGE, V68_DIGEST)?;
    assert_signature(V47A_POINT, V68_DIGEST, V68_REVEAL_SIGNATURE)?;
    assert_signature(V41_ROOT, V68_DIGEST, V68_ROOT_SIGNATURE)
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vector_69_compromised_key_state() -> TestResult {
    assert_vector(&v69_key_state()?, V69_PREIMAGE, V69_DIGEST)?;
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

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vector_47_prerotation_commitments() -> TestResult {
    assert_eq!(
        prerotation_commitment(&array(V47A_POINT)?),
        array::<32>(V47A_COMMITMENT)?
    );
    assert_eq!(
        prerotation_commitment(&array(V47B_POINT)?),
        array::<32>(V47B_COMMITMENT)?
    );
    Ok(())
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vectors_41_and_48_routing_ids() -> TestResult {
    let id = identifier(V41_IDENTIFIER)?;
    for (kind, expected) in [
        (RoutingKind::KeyEvents, V41_ROUTING_DID),
        (RoutingKind::CosignedHeads, V41_ROUTING_WIT),
        (RoutingKind::ConflictStatements, V41_ROUTING_WCF),
        (RoutingKind::ServiceRecord, V41_ROUTING_SVC),
    ] {
        assert_eq!(routing_id(kind, &id), array::<32>(expected)?);
    }
    assert_eq!(
        routing_id(RoutingKind::ServiceRecord, &identifier(V48_IDENTIFIER)?),
        array::<32>(V48_ADDRESS)?
    );
    Ok(())
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vector_57_identifier_text_form() -> TestResult {
    let id = identifier(V41_IDENTIFIER)?;
    assert_eq!(id.to_string(), V57_TEXT);
    assert_eq!(V57_TEXT.parse::<Identifier>()?, id);
    // Uppercase letters are outside the lowercase base32 alphabet.
    assert_eq!(
        V57_UPPERCASE.parse::<Identifier>(),
        non_canonical(NonCanonicalReason::Alphabet)
    );
    // Padding makes the body longer than 52 characters.
    assert_eq!(
        V57_PADDED.parse::<Identifier>(),
        non_canonical(NonCanonicalReason::Length)
    );
    // Not a spec 25 variant: one character short of the 56-character form.
    assert_eq!(
        V57_TEXT.get(..55).ok_or("short")?.parse::<Identifier>(),
        non_canonical(NonCanonicalReason::Length)
    );
    Ok(())
}
