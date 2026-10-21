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
//! - Differential against `serde_json`, a second RFC 8259 parser, with its
//!   recursion limit disabled so every depth the 512-byte bound admits is
//!   compared: a document the validator accepts is a JSON object whose
//!   top-level `type` and `challenge` are the strings the validator
//!   returned; a document the validator rejects as malformed JSON is one
//!   serde_json rejects too. Where serde_json's `Value` refuses a number it
//!   cannot convert, the comparison falls back to `IgnoredAny`, which checks
//!   the grammar without converting, and compares accept against reject.
//!   `IgnoredAny` decodes no string, so the fallback adds `std`'s UTF-8
//!   check and skips a lone-surrogate rejection: pairing surrogates in a
//!   document that also holds an out-of-range number is the one case
//!   neither serde_json pass decides, and every other document compares it.
//!   Duplicate names are skipped, because serde_json resolves them
//!   last-wins and the acceptance set is stricter by design; inputs outside
//!   1..=512 bytes are skipped, because the `AssertionSignature` bound
//!   rejects them before the validator runs.

use libfuzzer_sys::fuzz_target;
use scp_kel::{
    AssertionSignature, ClientDataError, IndexedSignature, SignatureForm, parse_client_data_json,
};
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::Value;

/// Parses `data` as `T` with serde_json's recursion limit disabled.
fn unbounded<'a, T: Deserialize<'a>>(data: &'a [u8]) -> serde_json::Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(data);
    deserializer.disable_recursion_limit();
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// The validator's verdict on whether `data` is JSON: `Some(true)` when it
/// read the whole document as JSON (accepted, or rejected only for its
/// top-level members), `Some(false)` when it found the bytes malformed, and
/// `None` when it stopped early on a rule serde_json does not share (a
/// duplicate name, a top level other than an object), so the rest of the
/// document was never judged.
const fn read_as_json(
    result: &Result<scp_kel::ClientDataMembers, ClientDataError>,
) -> Option<bool> {
    match result {
        Ok(_)
        | Err(
            ClientDataError::MissingType
            | ClientDataError::TypeNotString
            | ClientDataError::MissingChallenge
            | ClientDataError::ChallengeNotString,
        ) => Some(true),
        Err(ClientDataError::DuplicateMember { .. } | ClientDataError::TopLevelNotObject) => None,
        Err(_) => Some(false),
    }
}

fuzz_target!(|data: &[u8]| {
    for form in [SignatureForm::Raw, SignatureForm::WebAuthnAssertion] {
        if let Ok((signature, consumed)) = IndexedSignature::read(form, data) {
            assert_eq!(signature.to_bytes(), data[..consumed]);
        }
    }

    let Ok(assertion) = AssertionSignature::new(vec![0x05; 37], data.to_vec(), [0; 64]) else {
        return;
    };
    let ours = parse_client_data_json(&assertion);
    let theirs = unbounded::<Value>(data);
    if let Err(error) = &theirs {
        if error.to_string().contains("number out of range") {
            // `Value` converts numbers; `IgnoredAny` checks the grammar only.
            if matches!(ours, Err(ClientDataError::LoneSurrogate { .. })) {
                return;
            }
            if let Some(json) = read_as_json(&ours) {
                let grammar = unbounded::<IgnoredAny>(data);
                let utf8 = std::str::from_utf8(data).is_ok();
                assert_eq!(
                    json,
                    utf8 && grammar.is_ok(),
                    "accept/reject disagreement past the float range: {ours:?} vs utf8 {utf8}, {grammar:?}"
                );
            }
            return;
        }
    }
    match ours {
        Ok(members) => {
            let value = theirs.expect("the validator accepted JSON serde_json rejects");
            let object = value
                .as_object()
                .expect("an accepted top level is an object");
            assert_eq!(
                object.get("type").and_then(Value::as_str),
                Some(members.client_data_type.as_str())
            );
            assert_eq!(
                object.get("challenge").and_then(Value::as_str),
                Some(members.challenge.as_str())
            );
        }
        Err(ClientDataError::DuplicateMember { .. }) => {}
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
            let object = value
                .as_object()
                .expect("a validated top level is an object");
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
