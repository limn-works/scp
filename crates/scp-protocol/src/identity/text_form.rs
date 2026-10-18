//! The identifier's text form (`03-identity.md` §3.1, spec 25 Vector 57).
//!
//! An identifier's text form is `scp:` followed by the RFC 4648 base32
//! encoding of its 32 bytes, lowercase and unpadded: 56 characters in all.
//! The predicate here is syntactic: it decides whether a string is the one
//! canonical text of some 32-byte identifier, and resolves nothing.
//!
//! Its consumers are the identifier-scoped capability URI parser
//! (`07-trust-validation-and-capabilities.md` §7.3.4.1) and the identifier
//! type's text parser, which must call it (SCP-308).

/// The prefix every identifier text form starts with.
const PREFIX: &str = "scp:";

/// Characters of base32 for 32 bytes: `ceil(256 / 5)`.
const BODY_LEN: usize = 52;

/// Returns `true` when `s` is the canonical text form of a 32-byte identifier.
///
/// All of these hold for a canonical string:
/// - it starts with `scp:`;
/// - the rest is exactly 52 characters, each in the lowercase RFC 4648 base32
///   alphabet `[a-z2-7]` (no padding, no uppercase);
/// - the last character is `a` or `q`.
///
/// The last rule exists because 52 characters carry 260 bits for 256 bits of
/// identifier, so the final character's low 4 bits are zero in a canonical
/// encoding. A string whose last character sets any of them decodes to the
/// same 32 bytes as the canonical one, and §3.1 admits one text per
/// identifier.
#[must_use]
pub fn is_canonical_identifier_text(s: &str) -> bool {
    let Some(body) = s.strip_prefix(PREFIX) else {
        return false;
    };
    let bytes = body.as_bytes();
    if bytes.len() != BODY_LEN {
        return false;
    }
    if !bytes.iter().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return false;
    }
    // `a` encodes 0 and `q` encodes 16: the only values whose low 4 bits are zero.
    matches!(bytes[BODY_LEN - 1], b'a' | b'q')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Spec 25 Vector 57's accepted text form.
    const VECTOR_57: &str = "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za";
    /// The §25.1 fixture identifiers `proposer`, `new member` and `definer`.
    const PROPOSER: &str = "scp:flrkfgy6ehrwj35ay57p36ldffarlcmh2mj7smr7rauyvpreyqfa";
    const NEW_MEMBER: &str = "scp:ykcz3x3dycntc6lkxzbe3nixvd7w5c37riaowlh26lczdnc5vmja";
    const DEFINER: &str = "scp:tfgiiao36zlseo2tzfoi32knfx6topped3qloxcsube5gdvfrqgq";

    #[test]
    fn accepts_vector_57_and_section_25_1_fixtures() {
        for s in [VECTOR_57, PROPOSER, NEW_MEMBER, DEFINER] {
            assert!(is_canonical_identifier_text(s), "{s} must be canonical");
        }
    }

    #[test]
    fn rejects_vector_57_uppercase_and_padded_forms() {
        assert!(!is_canonical_identifier_text(
            "scp:FQHX6RDYX2KNWADYGEPPKG5DZSMTINRLB4KU3S7ZYWLVOLSGZ4ZA"
        ));
        assert!(!is_canonical_identifier_text(
            "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za===="
        ));
    }

    #[test]
    fn rejects_nonzero_trailing_bits() {
        // `b` encodes 1: the same 32 bytes as the canonical `...a` string.
        let s = format!("{}b", &VECTOR_57[..VECTOR_57.len() - 1]);
        assert!(!is_canonical_identifier_text(&s));
        // `r` encodes 17: the same 32 bytes as the canonical `...q` string.
        let s = format!("{}r", &DEFINER[..DEFINER.len() - 1]);
        assert!(!is_canonical_identifier_text(&s));
    }

    #[test]
    fn rejects_body_of_51_and_53_chars() {
        let short = format!("scp:{}", &VECTOR_57[5..]);
        assert_eq!(short.len(), 4 + 51);
        assert!(!is_canonical_identifier_text(&short));
        // Appended after the canonical text, so the 52nd body character is still
        // `a` and only the length rule rejects it.
        let long = format!("{VECTOR_57}a");
        assert_eq!(long.len(), 4 + 53);
        assert!(!is_canonical_identifier_text(&long));
    }

    #[test]
    fn rejects_wrong_prefix_and_alphabet() {
        assert!(!is_canonical_identifier_text(&VECTOR_57[4..]));
        assert!(!is_canonical_identifier_text(&format!(
            "did:{}",
            &VECTOR_57[4..]
        )));
        // `1`, `8`, `0` and `9` are outside the base32 alphabet.
        for bad in ['1', '8', '0', '9', ':', '-'] {
            let s = format!("scp:{bad}{}", &VECTOR_57[5..]);
            assert!(!is_canonical_identifier_text(&s), "{s}");
        }
        assert!(!is_canonical_identifier_text(""));
    }
}
