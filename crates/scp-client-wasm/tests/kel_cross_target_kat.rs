//! Cross-target known-answer tests for the key-event preimage, digest,
//! identifier, seal, commitment and routing ids, the two indexed-signature
//! forms (`09-security-model.md` §9.7.4.2, R13), the raw-form signatures spec
//! 25 prints for Vectors 51, 68 and 69, the event-unit decode
//! (`decode_event`, §9.10.12) of every spec 25 event, chain validation and
//! the key state each spec 25 chain replays to (§9.7.4.2 R3, R8), the raw
//! identifier, and the identifier's text form (`03-identity.md` §3.1).
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
    V41_ROUTING_SVC, V41_ROUTING_WCF, V41_ROUTING_WIT, V41_SIGNATURE, V42_AUTHENTICATOR_DATA,
    V42_CHALLENGE, V42_CHALLENGE_BYTES, V42_CLIENT_DATA_HASH, V42_CLIENT_DATA_JSON,
    V42_CLIENT_DATA_JSON_HEX, V42_DIGEST, V42_IDENTIFIER, V42_INDEXED_SIGNATURE, V42_PREIMAGE,
    V42_RP_ID, V42_SIGNATURE, V42_SIGNED_DIGEST, V42_SIGNED_MESSAGE, V47A_COMMITMENT, V47A_POINT,
    V47B_COMMITMENT, V47B_POINT, V48_ADDRESS, V48_IDENTIFIER, V50_DIGEST, V50_PREIMAGE, V50_SEAL,
    V50_SEALED_DIGEST, V50_SIGNATURE, V51_DIGEST, V51_IDENTIFIER, V51_INCEPTION_DIGEST,
    V51_INCEPTION_PREIMAGE, V51_INCEPTION_SIGNATURE, V51_KEYS, V51_PREIMAGE, V51_ROUTING_DID,
    V51_SIGNATURE, V53_DIGEST, V53_PREIMAGE, V53_SIGNATURE_FIELD, V54_DIGEST, V54_PREIMAGE,
    V54_SIGNATURE_FIELD, V55_DIGEST, V55_PREIMAGE, V55_SIGNATURE_FIELD, V68_DIGEST, V68_PREIMAGE,
    V68_REVEAL_SIGNATURE, V68_ROOT_SIGNATURE, V69_DIGEST, V69_PREIMAGE, V69_ROOT_SIGNATURE, array,
    assert_event_round_trip, assert_signature, assert_vector, bytes, event_unit, fields,
    identifier, read_unit, v41_inception, v50_key_state, v51_inception, v51_key_state,
    v68_rollover, v69_key_state,
};
use scp_did::{
    Identifier, IdentifierError, KeyCondition, KeyState, NonCanonicalReason, StandingCommitment,
};
use scp_kel::{
    Continuation, EventPreimage, IndexedSignature, KeyStateSnapshot, RoutingKind, SignatureForm,
    decode_preimage, derive_identifier, encode_preimage, key_event_challenge, key_event_seal,
    parse_client_data_json, prerotation_commitment, routing_id, verify_indexed,
};
use sha2::{Digest, Sha256};

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
        decode_preimage(&fields(V41_PREIMAGE)?)?.inception_identifier(),
        Some(identifier(V41_IDENTIFIER)?)
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

/// Every spec 25 event's unit decodes with each stage succeeding: the
/// header, the walked signature field, the body, the digest and `consumed`
/// match the printed bytes, on each target.
#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn every_event_unit_round_trips() -> TestResult {
    let reveal_then_root = format!("{V68_REVEAL_SIGNATURE}{V68_ROOT_SIGNATURE}");
    let events: [(&str, &str, &str); 10] = [
        (V41_PREIMAGE, V41_DIGEST, V41_SIGNATURE),
        (V42_PREIMAGE, V42_DIGEST, V42_INDEXED_SIGNATURE),
        (V50_PREIMAGE, V50_DIGEST, V50_SIGNATURE),
        (
            V51_INCEPTION_PREIMAGE,
            V51_INCEPTION_DIGEST,
            V51_INCEPTION_SIGNATURE,
        ),
        (V51_PREIMAGE, V51_DIGEST, V51_SIGNATURE),
        (V53_PREIMAGE, V53_DIGEST, V53_SIGNATURE_FIELD),
        (V54_PREIMAGE, V54_DIGEST, V54_SIGNATURE_FIELD),
        (V55_PREIMAGE, V55_DIGEST, V55_SIGNATURE_FIELD),
        (V68_PREIMAGE, V68_DIGEST, &reveal_then_root),
        (V69_PREIMAGE, V69_DIGEST, V69_ROOT_SIGNATURE),
    ];
    for (preimage, digest, signature_field) in events {
        assert_event_round_trip(preimage, digest, signature_field)?;
    }
    Ok(())
}

/// The identifier Vectors 41 and 42's received preimages recompute to is
/// each vector's printed identifier, on each target.
#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vectors_41_and_42_raw_identifier() -> TestResult {
    for (preimage, signature_field, printed) in [
        (V41_PREIMAGE, V41_SIGNATURE, V41_IDENTIFIER),
        (V42_PREIMAGE, V42_INDEXED_SIGNATURE, V42_IDENTIFIER),
    ] {
        let read = read_unit(&event_unit(preimage, signature_field)?)?;
        assert_eq!(read.raw().identifier(), identifier(printed)?);
    }
    Ok(())
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

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vector_41_raw_indexed_signature_verifies() -> TestResult {
    let field = fixtures::bytes(V41_SIGNATURE)?;
    let (signature, consumed) = IndexedSignature::read(SignatureForm::Raw, &field)?;
    assert_eq!(consumed, 64);
    verify_indexed(
        &array(V41_ROOT)?,
        &array(V41_DIGEST)?,
        SignatureForm::Raw,
        &signature,
    )?;
    Ok(())
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn vector_42_assertion_indexed_signature_verifies() -> TestResult {
    let field = fixtures::bytes(V42_INDEXED_SIGNATURE)?;
    let (signature, consumed) = IndexedSignature::read(SignatureForm::WebAuthnAssertion, &field)?;
    assert_eq!(consumed, field.len());
    assert_eq!(signature.to_bytes(), field);
    let IndexedSignature::WebAuthnAssertion(assertion) = &signature else {
        return Err("Vector 42 read as the raw form".into());
    };
    assert_eq!(
        assertion.authenticator_data(),
        fixtures::bytes(V42_AUTHENTICATOR_DATA)?
    );
    assert_eq!(
        assertion.client_data_json(),
        fixtures::bytes(V42_CLIENT_DATA_JSON_HEX)?
    );
    assert_eq!(
        assertion.client_data_json(),
        V42_CLIENT_DATA_JSON.as_bytes()
    );
    assert_eq!(assertion.signature(), &array::<64>(V42_SIGNATURE)?);

    // authenticatorData from its stated derivation: rpIdHash =
    // SHA-256("ctx.network"), flags 0x05, signCount 0.
    let authenticator = assertion.authenticator_data();
    assert_eq!(
        authenticator.get(..32).ok_or("short authenticatorData")?,
        Sha256::digest(V42_RP_ID.as_bytes()).as_slice()
    );
    assert_eq!(authenticator.get(32), Some(&0x05));
    assert_eq!(authenticator.get(33..), Some(&[0u8; 4][..]));

    let digest = array::<32>(V42_DIGEST)?;
    assert_eq!(
        key_event_challenge(&digest).as_slice(),
        fixtures::bytes(V42_CHALLENGE_BYTES)?
    );
    assert_eq!(parse_client_data_json(assertion)?.challenge, V42_CHALLENGE);
    let client_data_hash = Sha256::digest(assertion.client_data_json());
    assert_eq!(
        client_data_hash.as_slice(),
        fixtures::bytes(V42_CLIENT_DATA_HASH)?
    );
    let mut message = authenticator.to_vec();
    message.extend_from_slice(&client_data_hash);
    assert_eq!(message, fixtures::bytes(V42_SIGNED_MESSAGE)?);
    let signed = Sha256::digest(&message);
    assert_eq!(signed.as_slice(), fixtures::bytes(V42_SIGNED_DIGEST)?);

    verify_indexed(
        &array(V41_ROOT)?,
        &digest,
        SignatureForm::WebAuthnAssertion,
        &signature,
    )?;
    Ok(())
}

/// The one chain `validate_entry` returns over `units`, with every discard.
fn chain_verdict(
    identifier_hex: &str,
    units: &[&[u8]],
) -> Result<(scp_kel::ValidatedChain, Vec<scp_kel::Discarded>), Box<dyn std::error::Error>> {
    let validation = scp_kel::validate_entry(&identifier(identifier_hex)?, units);
    let scp_kel::EntryVerdict::Valid { chains } = &validation.verdict else {
        return Err(format!("expected Valid, got {:?}", validation.verdict).into());
    };
    let mut paths = chains.iter();
    match (paths.next(), paths.next()) {
        (Some(chain), None) => Ok((chain.clone(), validation.discarded)),
        _ => Err(format!("expected one chain, got {chains:?}").into()),
    }
}

/// `validate_entry` (§9.7.4.2 R3) accepts every spec 25 chain at the head
/// digest spec 25 prints, on both targets.
#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn spec_25_chains_validate() -> TestResult {
    let v41 = event_unit(V41_PREIMAGE, V41_SIGNATURE)?;
    let v68_signatures = format!("{V68_REVEAL_SIGNATURE}{V68_ROOT_SIGNATURE}");
    let successors = [
        (event_unit(V50_PREIMAGE, V50_SIGNATURE)?, V50_DIGEST),
        (event_unit(V53_PREIMAGE, V53_SIGNATURE_FIELD)?, V53_DIGEST),
        (event_unit(V54_PREIMAGE, V54_SIGNATURE_FIELD)?, V54_DIGEST),
        (event_unit(V55_PREIMAGE, V55_SIGNATURE_FIELD)?, V55_DIGEST),
        (event_unit(V68_PREIMAGE, &v68_signatures)?, V68_DIGEST),
        (event_unit(V69_PREIMAGE, V69_ROOT_SIGNATURE)?, V69_DIGEST),
    ];
    for (unit, digest) in &successors {
        let (chain, discarded) = chain_verdict(V41_IDENTIFIER, &[&v41, unit])?;
        assert!(discarded.is_empty(), "{discarded:?}");
        assert_eq!(chain.head_digest(), array::<32>(digest)?);
        assert_eq!(chain.head_sequence(), 1);
    }
    let v42 = event_unit(V42_PREIMAGE, V42_INDEXED_SIGNATURE)?;
    let (chain, discarded) = chain_verdict(V42_IDENTIFIER, &[&v42])?;
    assert!(discarded.is_empty(), "{discarded:?}");
    assert_eq!(chain.head_digest(), array::<32>(V42_DIGEST)?);
    let inception = event_unit(V51_INCEPTION_PREIMAGE, V51_INCEPTION_SIGNATURE)?;
    let key_state = event_unit(V51_PREIMAGE, V51_SIGNATURE)?;
    let (chain, discarded) = chain_verdict(V51_IDENTIFIER, &[&inception, &key_state])?;
    assert!(discarded.is_empty(), "{discarded:?}");
    assert_eq!(chain.head_digest(), array::<32>(V51_DIGEST)?);
    Ok(())
}

/// `validate_entry` discards a damaged unit at the step spec 09 names, with
/// the digest only a unit that reached step 6 carries, on both targets.
#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn damaged_units_are_discarded_at_their_step() -> TestResult {
    let v41 = event_unit(V41_PREIMAGE, V41_SIGNATURE)?;
    let v50 = event_unit(V50_PREIMAGE, V50_SIGNATURE)?;
    // The length prefix, the separator, then fields 1 to 12.
    let signature_at = 4 + 17 + fields(V50_PREIMAGE)?.len();
    let mut forged = v50.clone();
    *forged.get_mut(signature_at + 10).ok_or("short unit")? ^= 0x01;
    let mut unseparated = v50.clone();
    *unseparated.get_mut(4).ok_or("short unit")? ^= 0x01;
    let (chain, discarded) = chain_verdict(V41_IDENTIFIER, &[&v41, &forged, &unseparated])?;
    assert_eq!(chain.head_digest(), array::<32>(V41_DIGEST)?);
    let verdicts: Vec<_> = discarded
        .iter()
        .map(|discard| {
            (
                discard.served_index(),
                discard.read_for(),
                discard.stage(),
                discard.digest(),
            )
        })
        .collect();
    assert_eq!(
        verdicts,
        [
            (
                1,
                Some(1),
                scp_kel::CheckStep::VerifiedCount,
                Some(array::<32>(V50_DIGEST)?)
            ),
            (2, None, scp_kel::CheckStep::Separator, None),
        ]
    );
    // A clean copy of the damaged event merges with it (R9), so the chain
    // reaches Vector 50 and the damaged copy is no discard.
    let (chain, discarded) = chain_verdict(V41_IDENTIFIER, &[&v41, &forged, &unseparated, &v50])?;
    assert_eq!(chain.head_digest(), array::<32>(V50_DIGEST)?);
    assert_eq!(discarded.len(), 1, "{discarded:?}");
    Ok(())
}

/// Every spec 25 chain `validate_entry` accepts: its identifier, and each
/// event's printed preimage and signature field.
fn spec_25_chains() -> Vec<(&'static str, Vec<(&'static str, String)>)> {
    let v41 = || (V41_PREIMAGE, V41_SIGNATURE.to_owned());
    let on_v41 = |preimage, signature: &str| vec![v41(), (preimage, signature.to_owned())];
    vec![
        (V41_IDENTIFIER, vec![v41()]),
        (V41_IDENTIFIER, on_v41(V50_PREIMAGE, V50_SIGNATURE)),
        (V41_IDENTIFIER, on_v41(V53_PREIMAGE, V53_SIGNATURE_FIELD)),
        (V41_IDENTIFIER, on_v41(V54_PREIMAGE, V54_SIGNATURE_FIELD)),
        (V41_IDENTIFIER, on_v41(V55_PREIMAGE, V55_SIGNATURE_FIELD)),
        (
            V41_IDENTIFIER,
            on_v41(
                V68_PREIMAGE,
                &format!("{V68_REVEAL_SIGNATURE}{V68_ROOT_SIGNATURE}"),
            ),
        ),
        (V41_IDENTIFIER, on_v41(V69_PREIMAGE, V69_ROOT_SIGNATURE)),
        (
            V42_IDENTIFIER,
            vec![(V42_PREIMAGE, V42_INDEXED_SIGNATURE.to_owned())],
        ),
        (
            V51_IDENTIFIER,
            vec![
                (V51_INCEPTION_PREIMAGE, V51_INCEPTION_SIGNATURE.to_owned()),
                (V51_PREIMAGE, V51_SIGNATURE.to_owned()),
            ],
        ),
    ]
}

/// The latest event of `events` whose preimage `carries`, with its printed
/// hex.
fn latest<'e>(
    events: &'e [(&'static str, EventPreimage)],
    carries: impl Fn(&EventPreimage) -> bool,
) -> Result<&'e (&'static str, EventPreimage), Box<dyn std::error::Error>> {
    events
        .iter()
        .rev()
        .find(|(_, preimage)| carries(preimage))
        .ok_or_else(|| "no event of the chain carries the component".into())
}

/// Every spec 25 chain replays (§9.7.4.2 R8), and the replayed key state
/// encodes to spec 25's printed bytes on both targets: its snapshot, written
/// into the latest event that carries one, re-encodes that event's printed
/// preimage, and its standing commitment, written into the latest event that
/// carries a continuation, re-encodes that one's. An `Abandoned` commitment
/// names that event's sequence and the digest of its printed bytes. Native
/// and wasm32 each equal the spec bytes, so they equal each other.
#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn spec_25_chains_replay_to_their_printed_bytes() -> TestResult {
    for (identifier_hex, events) in spec_25_chains() {
        let units = events
            .iter()
            .map(|(preimage, signature)| event_unit(preimage, signature))
            .collect::<Result<Vec<_>, _>>()?;
        let refs: Vec<&[u8]> = units.iter().map(Vec::as_slice).collect();
        let (chain, discarded) = chain_verdict(identifier_hex, &refs)?;
        assert!(discarded.is_empty(), "{discarded:?}");
        let state = scp_kel::replay(&chain);
        let decoded = events
            .iter()
            .map(|(preimage, _)| {
                Ok((
                    *preimage,
                    decode_preimage(&fields(preimage)?)?.into_preimage(),
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let (head_hex, head) = decoded.last().ok_or("an empty chain")?;
        assert_eq!(state.identifier(), identifier(identifier_hex)?);
        assert_eq!(state.head_sequence(), head.sequence);
        assert_eq!(
            state.head_digest(),
            <[u8; 32]>::from(Sha256::digest(bytes(head_hex)?))
        );

        let KeyState {
            root_threshold,
            keys,
            witnesses,
            witnessing_interval,
            service_key_role,
            delegator,
            standing_commitment,
        } = state.key_state().clone();
        let (snapshot_hex, carrier) = latest(&decoded, |preimage| preimage.key_state.is_some())?;
        let rebuilt = EventPreimage {
            key_state: Some(KeyStateSnapshot {
                root_threshold,
                keys,
                witnesses,
                witnessing_interval,
                service_key_role,
                delegator,
            }),
            ..carrier.clone()
        };
        assert_eq!(
            encode_preimage(&rebuilt)?.signed_preimage(),
            bytes(snapshot_hex)?,
            "{identifier_hex}: the snapshot of {snapshot_hex:.16}"
        );

        let (commitment_hex, carrier) =
            latest(&decoded, |preimage| preimage.continuation.is_some())?;
        let continuation = match standing_commitment {
            StandingCommitment::Fixed(fixed) => Continuation::FixesCommitment(fixed),
            StandingCommitment::Abandoned {
                at_sequence,
                event_digest,
            } => {
                assert_eq!(at_sequence, carrier.sequence);
                assert_eq!(
                    event_digest,
                    <[u8; 32]>::from(Sha256::digest(bytes(commitment_hex)?))
                );
                Continuation::Abandons
            }
        };
        let rebuilt = EventPreimage {
            continuation: Some(continuation),
            ..carrier.clone()
        };
        assert_eq!(
            encode_preimage(&rebuilt)?.signed_preimage(),
            bytes(commitment_hex)?,
            "{identifier_hex}: the commitment of {commitment_hex:.16}"
        );
    }
    Ok(())
}
