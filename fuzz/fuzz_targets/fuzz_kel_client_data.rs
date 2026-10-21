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
//!   serde_json rejects too. serde_json reads a copy in which every number
//!   token outside a string is `0`: its `Value` refuses a number past the
//!   `f64` range, and a number's value is not in the acceptance set, so the
//!   rewrite leaves every verdict and every string as it was and the
//!   comparison runs on every document. Duplicate names are skipped,
//!   because serde_json resolves them last-wins and the acceptance set is
//!   stricter by design; inputs outside 1..=512 bytes are skipped, because
//!   the `AssertionSignature` bound rejects them before the validator runs.

use libfuzzer_sys::fuzz_target;
use scp_kel::{
    AssertionSignature, ClientDataError, IndexedSignature, SignatureForm, parse_client_data_json,
};
use serde_json::Value;

/// Parses `data` as a `Value` with serde_json's recursion limit disabled.
fn unbounded(data: &[u8]) -> serde_json::Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(data);
    deserializer.disable_recursion_limit();
    let value = serde::Deserialize::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// Whether `run` matches the RFC 8259 §6 number grammar
/// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`.
fn is_json_number(run: &[u8]) -> bool {
    fn digits(run: &[u8], at: usize) -> usize {
        run[at..].iter().take_while(|b| b.is_ascii_digit()).count()
    }
    let mut at = usize::from(run.first() == Some(&b'-'));
    match run.get(at) {
        Some(b'0') => at += 1,
        Some(b'1'..=b'9') => at += digits(run, at),
        _ => return false,
    }
    if run.get(at) == Some(&b'.') {
        let fraction = digits(run, at + 1);
        if fraction == 0 {
            return false;
        }
        at += 1 + fraction;
    }
    if matches!(run.get(at), Some(b'e' | b'E')) {
        at += 1;
        if matches!(run.get(at), Some(b'+' | b'-')) {
            at += 1;
        }
        let exponent = digits(run, at);
        if exponent == 0 {
            return false;
        }
        at += exponent;
    }
    at == run.len()
}

/// A copy of `data` in which every maximal run of number bytes outside a
/// string that is a well-formed JSON number becomes `0`. A run that is not a
/// well-formed number stays, so a malformed document stays malformed; a
/// number token in well-formed JSON is always such a run, since the bytes
/// around it (`:`, `,`, `[`, `]`, `}`, whitespace) are not number bytes.
fn zero_numbers(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut at = 0;
    let mut in_string = false;
    while let Some(&byte) = data.get(at) {
        if in_string {
            match byte {
                b'\\' => {
                    out.extend_from_slice(&data[at..(at + 2).min(data.len())]);
                    at += 2;
                    continue;
                }
                b'"' => in_string = false,
                _ => {}
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == b'-' || byte.is_ascii_digit() {
            let len = data[at..]
                .iter()
                .take_while(|b| matches!(b, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'))
                .count();
            let run = &data[at..at + len];
            if is_json_number(run) {
                out.push(b'0');
            } else {
                out.extend_from_slice(run);
            }
            at += len;
            continue;
        }
        out.push(byte);
        at += 1;
    }
    out
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
    let theirs = unbounded(&zero_numbers(data));
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
