#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! `clientDataJSON` acceptance-set fuzz target (Tier 2, trust boundary B3).
//!
//! An assertion-form key-event signature carries `clientDataJSON` bytes a
//! resolver fetched from the network, and `scp_kel::parse_client_data_json`
//! decides whether they are in the acceptance set (`09-security-model.md`
//! §9.7.4.2). Invariants:
//!
//! - I1: no input panics the validator, the indexed-signature reader, or
//!   the round trip of a read signature.
//! - Differential against `serde_json::Value`, a second RFC 8259 parser,
//!   wherever serde_json applies no rule of its own: a document the
//!   validator accepts is a JSON object whose top-level `type` and
//!   `challenge` are the strings the validator returned; a document the
//!   validator rejects as malformed JSON is one serde_json rejects too. The
//!   comparison is skipped where serde_json's own limits decide (its
//!   128-level nesting cap and its float conversion) and where the
//!   acceptance set is stricter by design (duplicate names, which serde_json
//!   resolves last-wins, and the 512-byte bound).

use libfuzzer_sys::fuzz_target;
use scp_kel::{ClientDataError, IndexedSignature, SignatureForm, parse_client_data_json};
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    for form in [SignatureForm::Raw, SignatureForm::WebAuthnAssertion] {
        if let Ok((signature, consumed)) = IndexedSignature::read(form, data) {
            assert_eq!(signature.to_bytes(), data[..consumed]);
        }
    }

    let ours = parse_client_data_json(data);
    let theirs = serde_json::from_slice::<Value>(data);
    if let Err(error) = &theirs {
        let message = error.to_string();
        if message.contains("recursion limit") || message.contains("number out of range") {
            return;
        }
    }
    match ours {
        Ok(members) => {
            let value = theirs.expect("the validator accepted JSON serde_json rejects");
            let object = value.as_object().expect("an accepted top level is an object");
            assert_eq!(
                object.get("type").and_then(Value::as_str),
                Some(members.client_data_type.as_str())
            );
            assert_eq!(
                object.get("challenge").and_then(Value::as_str),
                Some(members.challenge.as_str())
            );
        }
        Err(ClientDataError::TooLong { .. } | ClientDataError::DuplicateMember { .. }) => {}
        Err(ClientDataError::TopLevelNotObject) => {
            if let Ok(value) = theirs {
                assert!(!value.is_object(), "a top-level object was called not one");
            }
        }
        Err(
            error @ (ClientDataError::MissingType
            | ClientDataError::TypeNotString
            | ClientDataError::MissingChallenge
            | ClientDataError::ChallengeNotString),
        ) => {
            let value = theirs.expect("JSON the validator read whole is JSON to serde_json");
            let object = value.as_object().expect("a validated top level is an object");
            let type_string = object.get("type").and_then(Value::as_str).is_some();
            let challenge_string = object.get("challenge").and_then(Value::as_str).is_some();
            match error {
                ClientDataError::MissingType => assert!(!object.contains_key("type")),
                ClientDataError::TypeNotString => {
                    assert!(object.contains_key("type") && !type_string);
                }
                ClientDataError::MissingChallenge => {
                    assert!(type_string && !object.contains_key("challenge"));
                }
                _ => assert!(type_string && object.contains_key("challenge") && !challenge_string),
            }
        }
        Err(error) => {
            assert!(
                theirs.is_err(),
                "the validator rejected JSON serde_json accepts: {error}"
            );
        }
    }
});
