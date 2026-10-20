//! The `clientDataJSON` acceptance set, rule by rule
//! (`09-security-model.md` §9.7.4.2). Each reject case breaks exactly one
//! rule of a document that is otherwise accepted.

use scp_kel::{ClientDataError, ClientDataMembers, parse_client_data_json};

use crate::fixtures::{TestResult, V42_CHALLENGE, V42_CLIENT_DATA_JSON};

fn members(challenge: &str) -> ClientDataMembers {
    ClientDataMembers {
        client_data_type: "webauthn.get".to_owned(),
        challenge: challenge.to_owned(),
    }
}

#[test]
fn vector_42_client_data_is_accepted() -> TestResult {
    assert_eq!(
        parse_client_data_json(V42_CLIENT_DATA_JSON.as_bytes())?,
        members(V42_CHALLENGE)
    );
    Ok(())
}

#[test]
fn a_byte_order_mark_is_rejected() {
    let mut document = vec![0xEF, 0xBB, 0xBF];
    document.extend_from_slice(V42_CLIENT_DATA_JSON.as_bytes());
    assert_eq!(
        parse_client_data_json(&document),
        Err(ClientDataError::ByteOrderMark)
    );
}

#[test]
fn input_that_is_not_strict_utf8_is_rejected() {
    // A lone continuation byte, an overlong `/`, and an encoded surrogate.
    for bad in [&[0x80][..], &[0xC0, 0xAF], &[0xED, 0xA0, 0x80]] {
        let mut document = br#"{"type":"webauthn.get","challenge":"a","x":""#.to_vec();
        let offset = document.len();
        document.extend_from_slice(bad);
        document.extend_from_slice(br#""}"#);
        assert_eq!(
            parse_client_data_json(&document),
            Err(ClientDataError::InvalidUtf8 { offset })
        );
    }
}

#[test]
fn lone_surrogate_escapes_are_rejected() {
    for (document, offset) in [
        (r#"{"type":"webauthn.get","challenge":"\ud800"}"#, 36),
        (r#"{"type":"webauthn.get","challenge":"\udc00"}"#, 36),
        (r#"{"type":"webauthn.get","challenge":"\ud800\u0041"}"#, 36),
    ] {
        assert_eq!(
            parse_client_data_json(document.as_bytes()),
            Err(ClientDataError::LoneSurrogate { offset })
        );
    }
}

#[test]
fn a_surrogate_pair_escape_decodes_to_one_character() -> TestResult {
    let parsed =
        parse_client_data_json(r#"{"type":"webauthn.get","challenge":"\ud83d\ude00"}"#.as_bytes())?;
    assert_eq!(parsed.challenge, "\u{1F600}");
    Ok(())
}

#[test]
fn an_unescaped_control_character_is_rejected() {
    assert_eq!(
        parse_client_data_json(b"{\"type\":\"webauthn.get\",\"challenge\":\"a\tb\"}"),
        Err(ClientDataError::UnescapedControl { offset: 37 })
    );
}

#[test]
fn trailing_non_whitespace_is_rejected_and_whitespace_is_accepted() -> TestResult {
    let document = format!("{V42_CLIENT_DATA_JSON} \r\n\t");
    parse_client_data_json(document.as_bytes())?;
    let document = format!("{V42_CLIENT_DATA_JSON} x");
    assert_eq!(
        parse_client_data_json(document.as_bytes()),
        Err(ClientDataError::TrailingContent { offset: 156 })
    );
    let document = format!("{V42_CLIENT_DATA_JSON}{{}}");
    assert_eq!(
        parse_client_data_json(document.as_bytes()),
        Err(ClientDataError::TrailingContent { offset: 155 })
    );
    Ok(())
}

#[test]
fn a_top_level_value_other_than_an_object_is_rejected() {
    for document in [
        r#"["type","webauthn.get"]"#,
        r#""webauthn.get""#,
        "1",
        "null",
    ] {
        assert_eq!(
            parse_client_data_json(document.as_bytes()),
            Err(ClientDataError::TopLevelNotObject)
        );
    }
    assert_eq!(
        parse_client_data_json(b" "),
        Err(ClientDataError::UnexpectedEnd)
    );
}

#[test]
fn a_duplicate_name_is_rejected_at_every_depth() {
    for (document, offset) in [
        // The PRD's case.
        (r#"{"challenge":"a","challenge":"b"}"#, 17),
        // Three levels deep.
        (r#"{"x":{"y":{"k":1,"k":2}}}"#, 17),
        // Three levels deep, equal only after unescaping.
        (r#"{"x":{"y":{"k":1,"\u006b":2}}}"#, 17),
        // Inside an array element.
        (r#"{"x":[{"k":1,"k":2}]}"#, 13),
    ] {
        assert_eq!(
            parse_client_data_json(document.as_bytes()),
            Err(ClientDataError::DuplicateMember { offset }),
            "{document}"
        );
    }
}

#[test]
fn equal_names_in_sibling_objects_are_not_duplicates() -> TestResult {
    parse_client_data_json(
        r#"{"type":"webauthn.get","challenge":"a","x":{"k":1},"y":{"k":2},"z":[{"k":1},{"k":2}]}"#
            .as_bytes(),
    )?;
    Ok(())
}

#[test]
fn a_number_past_every_float_range_is_accepted_unconverted() -> TestResult {
    let parsed = parse_client_data_json(
        r#"{"type":"webauthn.get","challenge":"a","n":1e400,"m":-0.5E-400,"k":123456789012345678901234567890}"#
            .as_bytes(),
    )?;
    assert_eq!(parsed, members("a"));
    Ok(())
}

#[test]
fn numbers_outside_the_rfc_8259_grammar_are_rejected() {
    for number in ["01", "1.", ".5", "1e", "1e+", "-", "+1", "0x10", "NaN"] {
        let document = format!(r#"{{"type":"webauthn.get","challenge":"a","n":{number}}}"#);
        assert!(
            parse_client_data_json(document.as_bytes()).is_err(),
            "{number} accepted"
        );
    }
}

/// 250 nested arrays inside 512 bytes are valid JSON; the parser accepts
/// the document and stops only at the missing `type`, which shows that no
/// depth limit rejected it.
#[test]
fn nesting_250_deep_within_the_bound_is_accepted() {
    let document = format!(r#"{{"a":{}{}}}"#, "[".repeat(250), "]".repeat(250));
    assert!(document.len() <= 512);
    assert_eq!(
        parse_client_data_json(document.as_bytes()),
        Err(ClientDataError::MissingType)
    );
}

#[test]
fn unknown_members_are_ignored() -> TestResult {
    let parsed = parse_client_data_json(
        r#"{"origin":"x","type":"webauthn.get","tokenBinding":{"status":"present"},"challenge":"a","other_keys_can_be_added_here":true}"#
            .as_bytes(),
    )?;
    assert_eq!(parsed, members("a"));
    Ok(())
}

#[test]
fn type_and_challenge_are_read_from_the_top_level_only() {
    assert_eq!(
        parse_client_data_json(
            r#"{"challenge":"a","x":{"type":"webauthn.get"},"y":[{"type":"webauthn.get"}]}"#
                .as_bytes()
        ),
        Err(ClientDataError::MissingType)
    );
    assert_eq!(
        parse_client_data_json(r#"{"type":"webauthn.get","x":{"challenge":"a"}}"#.as_bytes()),
        Err(ClientDataError::MissingChallenge)
    );
}

#[test]
fn type_and_challenge_must_be_strings() {
    for (document, error) in [
        (
            r#"{"type":1,"challenge":"a"}"#,
            ClientDataError::TypeNotString,
        ),
        (
            r#"{"type":{},"challenge":"a"}"#,
            ClientDataError::TypeNotString,
        ),
        (
            r#"{"type":"webauthn.get","challenge":true}"#,
            ClientDataError::ChallengeNotString,
        ),
        (
            r#"{"type":"webauthn.get","challenge":["a"]}"#,
            ClientDataError::ChallengeNotString,
        ),
    ] {
        assert_eq!(
            parse_client_data_json(document.as_bytes()),
            Err(error),
            "{document}"
        );
    }
}

#[test]
fn escapes_decode_to_their_characters() -> TestResult {
    let parsed = parse_client_data_json(
        r#"{"type":"web\u0061uthn.get","challenge":"\"\\\/\b\f\n\r\t\u00e9"}"#.as_bytes(),
    )?;
    assert_eq!(parsed.client_data_type, "webauthn.get");
    assert_eq!(parsed.challenge, "\"\\/\u{8}\u{c}\n\r\t\u{e9}");
    Ok(())
}

#[test]
fn malformed_escapes_and_structure_are_rejected() {
    for document in [
        r#"{"type":"webauthn.get","challenge":"\x"}"#,
        r#"{"type":"webauthn.get","challenge":"\u00g0"}"#,
        r#"{"type":"webauthn.get","challenge":"a",}"#,
        r#"{"type":"webauthn.get","challenge":"a""#,
        r#"{"type":"webauthn.get" "challenge":"a"}"#,
        r#"{"type":"webauthn.get","challenge":"a","x":[1,]}"#,
        r#"{"type":"webauthn.get","challenge":"a","x":tru}"#,
        r#"{type:"webauthn.get"}"#,
        r#"{"type":"webauthn.get","challenge":"a","x":]}"#,
        r#"{"type":"webauthn.get","challenge":"a","x":[}"#,
    ] {
        assert!(
            parse_client_data_json(document.as_bytes()).is_err(),
            "{document} accepted"
        );
    }
}

#[test]
fn the_length_bound_is_512_bytes() -> TestResult {
    let base = r#"{"type":"webauthn.get","challenge":"a","p":""}"#;
    let fill = 512 - base.len();
    let at_bound = format!(
        r#"{{"type":"webauthn.get","challenge":"a","p":"{}"}}"#,
        "x".repeat(fill)
    );
    assert_eq!(at_bound.len(), 512);
    parse_client_data_json(at_bound.as_bytes())?;
    let over = format!("{at_bound} ");
    assert_eq!(
        parse_client_data_json(over.as_bytes()),
        Err(ClientDataError::TooLong { len: 513 })
    );
    Ok(())
}
