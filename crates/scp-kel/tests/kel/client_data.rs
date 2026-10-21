//! The `clientDataJSON` acceptance set, rule by rule
//! (`09-security-model.md` §9.7.4.2). Each reject row breaks exactly one
//! rule of a document that is otherwise accepted and asserts the variant
//! that rule returns; each accept row exercises one grammar branch.

use scp_kel::{AssertionSignature, ClientDataError, ClientDataMembers, parse_client_data_json};

use crate::fixtures::{TestResult, V42_CHALLENGE, V42_CLIENT_DATA_JSON};

type Error = Box<dyn std::error::Error>;

/// Validates `document` as the `clientDataJSON` of an assertion, the only
/// bytes the validator runs over.
fn parse(document: &[u8]) -> Result<Result<ClientDataMembers, ClientDataError>, Error> {
    let assertion = AssertionSignature::new(vec![0x05; 37], document.to_vec(), [0; 64])?;
    Ok(parse_client_data_json(&assertion))
}

fn members(challenge: &str) -> ClientDataMembers {
    ClientDataMembers {
        client_data_type: "webauthn.get".to_owned(),
        challenge: challenge.to_owned(),
    }
}

#[test]
fn vector_42_client_data_is_accepted() -> TestResult {
    assert_eq!(
        parse(V42_CLIENT_DATA_JSON.as_bytes())??,
        members(V42_CHALLENGE)
    );
    Ok(())
}

#[test]
fn a_byte_order_mark_is_rejected() -> TestResult {
    let mut document = vec![0xEF, 0xBB, 0xBF];
    document.extend_from_slice(V42_CLIENT_DATA_JSON.as_bytes());
    assert_eq!(parse(&document)?, Err(ClientDataError::ByteOrderMark));
    Ok(())
}

#[test]
fn input_that_is_not_strict_utf8_is_rejected() -> TestResult {
    // A lone continuation byte, an overlong `/`, an encoded surrogate, and a
    // code point above U+10FFFF.
    for bad in [
        &[0x80][..],
        &[0xC0, 0xAF],
        &[0xED, 0xA0, 0x80],
        &[0xF4, 0x90, 0x80, 0x80],
    ] {
        let mut document = br#"{"type":"webauthn.get","challenge":"a","x":""#.to_vec();
        let offset = document.len();
        document.extend_from_slice(bad);
        document.extend_from_slice(br#""}"#);
        assert_eq!(
            parse(&document)?,
            Err(ClientDataError::InvalidUtf8 { offset }),
            "{bad:02x?}"
        );
    }
    Ok(())
}

#[test]
fn a_surrogate_pair_escape_decodes_to_one_character() -> TestResult {
    let parsed = parse(br#"{"type":"webauthn.get","challenge":"\ud83d\ude00"}"#)??;
    assert_eq!(parsed.challenge, "\u{1F600}");
    Ok(())
}

#[test]
fn escapes_decode_to_their_characters() -> TestResult {
    let parsed = parse(br#"{"type":"web\u0061uthn.get","challenge":"\"\\\/\b\f\n\r\t\u00e9"}"#)??;
    assert_eq!(parsed.client_data_type, "webauthn.get");
    assert_eq!(parsed.challenge, "\"\\/\u{8}\u{c}\n\r\t\u{e9}");
    Ok(())
}

#[test]
fn trailing_non_whitespace_is_rejected_and_whitespace_is_accepted() -> TestResult {
    let document = format!("{V42_CLIENT_DATA_JSON} \r\n\t");
    parse(document.as_bytes())??;
    let document = format!("{V42_CLIENT_DATA_JSON} x");
    assert_eq!(
        parse(document.as_bytes())?,
        Err(ClientDataError::TrailingContent { offset: 156 })
    );
    let document = format!("{V42_CLIENT_DATA_JSON}{{}}");
    assert_eq!(
        parse(document.as_bytes())?,
        Err(ClientDataError::TrailingContent { offset: 155 })
    );
    Ok(())
}

#[test]
fn a_top_level_value_other_than_an_object_is_rejected() -> TestResult {
    for document in [
        r#"["type","webauthn.get"]"#,
        r#""webauthn.get""#,
        "1",
        "null",
    ] {
        assert_eq!(
            parse(document.as_bytes())?,
            Err(ClientDataError::TopLevelNotObject)
        );
    }
    assert_eq!(parse(b" ")?, Err(ClientDataError::UnexpectedEnd));
    Ok(())
}

#[test]
fn a_duplicate_name_is_rejected_at_every_depth() -> TestResult {
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
            parse(document.as_bytes())?,
            Err(ClientDataError::DuplicateMember { offset }),
            "{document}"
        );
    }
    Ok(())
}

/// One row per rule: the document breaks that rule alone, and the row
/// carries the variant and offset that rule returns.
const REJECTIONS: &[(&str, &[u8], ClientDataError)] = &[
    (
        "an undefined escape",
        br#"{"type":"webauthn.get","challenge":"a","x":"\x"}"#,
        ClientDataError::InvalidEscape { offset: 44 },
    ),
    (
        "a non-hex digit in a \\u escape",
        br#"{"type":"webauthn.get","challenge":"a","x":"\u00g0"}"#,
        ClientDataError::InvalidEscape { offset: 44 },
    ),
    (
        "a non-hex digit in the low half of a surrogate pair",
        br#"{"type":"webauthn.get","challenge":"a","x":"\ud800\u00g0"}"#,
        ClientDataError::InvalidEscape { offset: 50 },
    ),
    (
        "a high surrogate with no low half",
        br#"{"type":"webauthn.get","challenge":"a","x":"\ud800"}"#,
        ClientDataError::LoneSurrogate { offset: 44 },
    ),
    (
        "a low surrogate with no high half",
        br#"{"type":"webauthn.get","challenge":"a","x":"\udc00"}"#,
        ClientDataError::LoneSurrogate { offset: 44 },
    ),
    (
        "a high surrogate followed by a non-surrogate",
        br#"{"type":"webauthn.get","challenge":"a","x":"\ud800\u0041"}"#,
        ClientDataError::LoneSurrogate { offset: 44 },
    ),
    (
        "a raw NUL inside a string",
        b"{\"type\":\"webauthn.get\",\"challenge\":\"a\",\"x\":\"a\x00b\"}",
        ClientDataError::UnescapedControl { offset: 45 },
    ),
    (
        "a raw tab inside a string",
        b"{\"type\":\"webauthn.get\",\"challenge\":\"a\",\"x\":\"a\x09b\"}",
        ClientDataError::UnescapedControl { offset: 45 },
    ),
    (
        "a raw 0x1F inside a string",
        b"{\"type\":\"webauthn.get\",\"challenge\":\"a\",\"x\":\"a\x1fb\"}",
        ClientDataError::UnescapedControl { offset: 45 },
    ),
    (
        "a trailing comma in an object",
        br#"{"type":"webauthn.get","challenge":"a",}"#,
        ClientDataError::UnexpectedByte {
            offset: 39,
            byte: b'}',
        },
    ),
    (
        "a trailing comma in an array",
        br#"{"type":"webauthn.get","challenge":"a","x":[1,]}"#,
        ClientDataError::UnexpectedByte {
            offset: 46,
            byte: b']',
        },
    ),
    (
        "a missing comma between members",
        br#"{"type":"webauthn.get","challenge":"a" "x":1}"#,
        ClientDataError::UnexpectedByte {
            offset: 39,
            byte: b'"',
        },
    ),
    (
        "a missing colon",
        br#"{"type":"webauthn.get","challenge":"a","x" 1}"#,
        ClientDataError::UnexpectedByte {
            offset: 43,
            byte: b'1',
        },
    ),
    (
        "an unquoted name",
        br#"{type:"webauthn.get"}"#,
        ClientDataError::UnexpectedByte {
            offset: 1,
            byte: b't',
        },
    ),
    (
        "a truncated literal",
        br#"{"type":"webauthn.get","challenge":"a","x":tru}"#,
        ClientDataError::UnexpectedByte {
            offset: 43,
            byte: b't',
        },
    ),
    (
        "a close where a value belongs",
        br#"{"type":"webauthn.get","challenge":"a","x":]}"#,
        ClientDataError::UnexpectedByte {
            offset: 43,
            byte: b']',
        },
    ),
    (
        "an object close in an empty array",
        br#"{"type":"webauthn.get","challenge":"a","x":[}"#,
        ClientDataError::UnexpectedByte {
            offset: 44,
            byte: b'}',
        },
    ),
    (
        "an array closed by }",
        br#"{"type":"webauthn.get","challenge":"a","x":[1}}"#,
        ClientDataError::UnexpectedByte {
            offset: 45,
            byte: b'}',
        },
    ),
    (
        "an object closed by ]",
        br#"{"type":"webauthn.get","challenge":"a","x":{"a":1]}"#,
        ClientDataError::UnexpectedByte {
            offset: 49,
            byte: b']',
        },
    ),
    (
        "an unclosed object",
        br#"{"type":"webauthn.get","challenge":"a""#,
        ClientDataError::UnexpectedEnd,
    ),
    (
        "an unclosed string",
        br#"{"type":"webauthn.get","challenge":"a","x":"a"#,
        ClientDataError::UnexpectedEnd,
    ),
    (
        "the number 01",
        br#"{"type":"webauthn.get","challenge":"a","n":01}"#,
        ClientDataError::UnexpectedByte {
            offset: 44,
            byte: b'1',
        },
    ),
    (
        "the number 1.",
        br#"{"type":"webauthn.get","challenge":"a","n":1.}"#,
        ClientDataError::InvalidNumber { offset: 43 },
    ),
    (
        "the number 1.e5",
        br#"{"type":"webauthn.get","challenge":"a","n":1.e5}"#,
        ClientDataError::InvalidNumber { offset: 43 },
    ),
    (
        "the number 1e",
        br#"{"type":"webauthn.get","challenge":"a","n":1e}"#,
        ClientDataError::InvalidNumber { offset: 43 },
    ),
    (
        "the number 1e+",
        br#"{"type":"webauthn.get","challenge":"a","n":1e+}"#,
        ClientDataError::InvalidNumber { offset: 43 },
    ),
    (
        "the number -",
        br#"{"type":"webauthn.get","challenge":"a","n":-}"#,
        ClientDataError::InvalidNumber { offset: 43 },
    ),
    (
        "the number -a",
        br#"{"type":"webauthn.get","challenge":"a","n":-a}"#,
        ClientDataError::InvalidNumber { offset: 43 },
    ),
    (
        "the number .5",
        br#"{"type":"webauthn.get","challenge":"a","n":.5}"#,
        ClientDataError::UnexpectedByte {
            offset: 43,
            byte: b'.',
        },
    ),
    (
        "the number +1",
        br#"{"type":"webauthn.get","challenge":"a","n":+1}"#,
        ClientDataError::UnexpectedByte {
            offset: 43,
            byte: b'+',
        },
    ),
    (
        "the number 0x10",
        br#"{"type":"webauthn.get","challenge":"a","n":0x10}"#,
        ClientDataError::UnexpectedByte {
            offset: 44,
            byte: b'x',
        },
    ),
    (
        "the number NaN",
        br#"{"type":"webauthn.get","challenge":"a","n":NaN}"#,
        ClientDataError::UnexpectedByte {
            offset: 43,
            byte: b'N',
        },
    ),
];

/// Every [`REJECTIONS`] row is rejected with its own variant and offset.
#[test]
fn each_rule_rejects_with_its_own_variant() -> TestResult {
    for (rule, document, error) in REJECTIONS {
        assert_eq!(parse(document)?, Err(error.clone()), "{rule}");
    }
    Ok(())
}

/// One row per grammar branch a real assertion can take: each document is
/// accepted with its top-level members.
#[test]
fn each_grammar_branch_accepts() -> TestResult {
    let rows: &[(&str, &[u8], &str)] = &[
        (
            "whitespace around every token and a space inside a string",
            b"{ \"type\" : \"webauthn.get\" ,\x0d\x0a\x09\"challenge\" : \"a b\" }",
            "a b",
        ),
        (
            "a raw DEL inside a string",
            b"{\"type\":\"webauthn.get\",\"challenge\":\"a\x7f\"}",
            "a\u{7f}",
        ),
        (
            "equal names in sibling objects",
            br#"{"type":"webauthn.get","challenge":"a","x":{"k":1},"y":{"k":2},"z":[{"k":1},{"k":2}]}"#,
            "a",
        ),
        (
            "a child object reusing its parent's member names",
            br#"{"type":"webauthn.get","challenge":"a","x":{"type":1,"challenge":2,"x":{"x":3}}}"#,
            "a",
        ),
        (
            "numbers past every float range, unconverted",
            br#"{"type":"webauthn.get","challenge":"a","n":1e400,"m":-0.5E-400,"k":123456789012345678901234567890}"#,
            "a",
        ),
        (
            "every number form the grammar admits",
            br#"{"type":"webauthn.get","challenge":"a","n":[0,-0,0.0,10,-1.25,1e5,1E+5,1e-5,2.5e05]}"#,
            "a",
        ),
        (
            "the literals and empty containers",
            br#"{"type":"webauthn.get","challenge":"a","n":[true,false,null,{},[],""]}"#,
            "a",
        ),
        (
            "unknown members, including Chrome's",
            br#"{"origin":"x","type":"webauthn.get","tokenBinding":{"status":"present"},"challenge":"a","other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}"#,
            "a",
        ),
    ];
    for (branch, document, challenge) in rows {
        assert_eq!(parse(document)?, Ok(members(challenge)), "{branch}");
    }
    Ok(())
}

/// 250 nested arrays inside 512 bytes are valid JSON; the parser accepts
/// the document and stops only at the missing `type`, which shows that no
/// depth limit rejected it.
#[test]
fn nesting_250_deep_within_the_bound_is_accepted() -> TestResult {
    let document = format!(r#"{{"a":{}{}}}"#, "[".repeat(250), "]".repeat(250));
    assert!(document.len() <= 512);
    assert_eq!(
        parse(document.as_bytes())?,
        Err(ClientDataError::MissingType)
    );
    Ok(())
}

#[test]
fn type_and_challenge_are_read_from_the_top_level_only() -> TestResult {
    assert_eq!(
        parse(br#"{"challenge":"a","x":{"type":"webauthn.get"},"y":[{"type":"webauthn.get"}]}"#)?,
        Err(ClientDataError::MissingType)
    );
    assert_eq!(
        parse(br#"{"type":"webauthn.get","x":{"challenge":"a"}}"#)?,
        Err(ClientDataError::MissingChallenge)
    );
    Ok(())
}

#[test]
fn type_and_challenge_must_be_strings() -> TestResult {
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
        assert_eq!(parse(document.as_bytes())?, Err(error), "{document}");
    }
    Ok(())
}
