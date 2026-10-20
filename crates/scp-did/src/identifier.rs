//! The identity identifier and its text form (`03-identity.md` §3.1;
//! `09-security-model.md` §9.7.4.2 R13; spec 25 Vector 57).
//!
//! An identifier is the 32-byte digest of an inception event's signed
//! preimage. Its one canonical text form is `scp:` followed by the RFC 4648
//! base32 encoding of those 32 bytes, lowercase and unpadded: 52 base32
//! characters and 56 characters in all. A parser rejects every other string,
//! uppercase or padded base32 and a DID string included, with
//! [`IdentifierError::NonCanonicalIdentifier`], which the identity API maps to
//! `IdentityError::NonCanonicalIdentifier` (SCP-IDENT-1106, `03-identity.md`
//! §3.10.10).

use std::fmt;
use std::str::FromStr;

use data_encoding::{BASE32_NOPAD_NOCASE, DecodeKind};

/// The prefix every identifier text form starts with.
const PREFIX: &str = "scp:";

/// Characters of base32 for 32 bytes: `ceil(256 / 5)`.
const BODY_LEN: usize = 52;

/// An identity's identifier: the 32-byte digest of its inception event's
/// signed preimage (`09-security-model.md` §9.7.4.2 R13).
///
/// `Ord` is unsigned byte order over the 32 bytes, which the §9.11 key
/// continuity construction relies on to order the two parties.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identifier([u8; 32]);

impl Identifier {
    /// The all-zero identifier, which the inception event carries in its
    /// `identifier` field because the identifier is the digest of that event
    /// (`09-security-model.md` §9.7.4.2 preimage field 2).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Wraps 32 raw identifier bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 raw identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Writes the canonical text form: `scp:` and 52 lowercase, unpadded RFC 4648
/// base32 characters (`03-identity.md` §3.1).
impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let body = BASE32_NOPAD_NOCASE.encode(&self.0).to_ascii_lowercase();
        write!(f, "{PREFIX}{body}")
    }
}

/// Parses only the canonical text form. The string is checked against the
/// canonical-text predicate before any decoding, and it is never lowercased,
/// trimmed or unpadded first, so §3.1 admits exactly one text per identifier.
impl FromStr for Identifier {
    type Err = IdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        check_canonical_identifier_text(s).map_err(IdentifierError::from)?;
        let body = s
            .strip_prefix(PREFIX)
            .ok_or(IdentifierError::NonCanonicalIdentifier {
                reason: NonCanonicalReason::Prefix,
            })?;
        let decoded = BASE32_NOPAD_NOCASE
            .decode(body.as_bytes())
            .map_err(|e| IdentifierError::from(reason_for_decode_kind(e.kind)))?;
        let bytes = <[u8; 32]>::try_from(decoded.as_slice())
            .map_err(|_| IdentifierError::from(NonCanonicalReason::Length))?;
        Ok(Self(bytes))
    }
}

/// Why a string is not the canonical text form of an identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NonCanonicalReason {
    /// The string does not start with `scp:`.
    Prefix,
    /// The text after `scp:` is not exactly 52 characters.
    Length,
    /// A character after `scp:` is outside the lowercase RFC 4648 base32
    /// alphabet `[a-z2-7]`, which excludes uppercase and `=` padding.
    Alphabet,
    /// The last character sets one of the 4 bits beyond the identifier's 256,
    /// so the string decodes to the same bytes as the canonical one.
    TrailingBits,
}

impl fmt::Display for NonCanonicalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Prefix => "missing the scp: prefix",
            Self::Length => "not 52 base32 characters after the prefix",
            Self::Alphabet => "a character outside the lowercase base32 alphabet",
            Self::TrailingBits => "nonzero trailing bits in the last character",
        })
    }
}

/// The error parsing an identifier's text form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdentifierError {
    /// The string is not the one canonical text form `03-identity.md` §3.1
    /// defines. The identity API maps this variant to
    /// `IdentityError::NonCanonicalIdentifier` (SCP-IDENT-1106, §3.10.10).
    #[error("non-canonical identifier text: {reason}")]
    NonCanonicalIdentifier {
        /// Which canonical-form rule the string breaks.
        reason: NonCanonicalReason,
    },
}

impl From<NonCanonicalReason> for IdentifierError {
    fn from(reason: NonCanonicalReason) -> Self {
        Self::NonCanonicalIdentifier { reason }
    }
}

/// Maps a base32 decoder rejection to the canonical-form rule it reflects.
const fn reason_for_decode_kind(kind: DecodeKind) -> NonCanonicalReason {
    match kind {
        DecodeKind::Length => NonCanonicalReason::Length,
        DecodeKind::Symbol | DecodeKind::Padding => NonCanonicalReason::Alphabet,
        DecodeKind::Trailing => NonCanonicalReason::TrailingBits,
    }
}

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
///
/// The predicate is syntactic: it resolves nothing. Its consumers are
/// [`Identifier`]'s text parser and the identifier-scoped capability URI
/// parser (`07-trust-validation-and-capabilities.md` §7.3.4.1).
#[must_use]
pub fn is_canonical_identifier_text(s: &str) -> bool {
    check_canonical_identifier_text(s).is_ok()
}

/// The canonical-text predicate, naming the first rule a string breaks.
fn check_canonical_identifier_text(s: &str) -> Result<(), NonCanonicalReason> {
    let body = s.strip_prefix(PREFIX).ok_or(NonCanonicalReason::Prefix)?;
    let bytes = body.as_bytes();
    if bytes.len() != BODY_LEN {
        return Err(NonCanonicalReason::Length);
    }
    if !bytes.iter().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return Err(NonCanonicalReason::Alphabet);
    }
    // `a` encodes 0 and `q` encodes 16: the only values whose low 4 bits are zero.
    match bytes.last() {
        Some(b'a' | b'q') => Ok(()),
        _ => Err(NonCanonicalReason::TrailingBits),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Spec 25 Vector 57's identifier, which is Vector 41's.
    const VECTOR_57_HEX: &str = "2c0f7f4478be94db0078311ef51ba3cc9934362b0f154dcbf9c597572e46cf32";
    /// Spec 25 Vector 57's accepted text form.
    const VECTOR_57: &str = "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za";
    /// Spec 25 Vector 57's rejected uppercase form.
    const VECTOR_57_UPPER: &str = "scp:FQHX6RDYX2KNWADYGEPPKG5DZSMTINRLB4KU3S7ZYWLVOLSGZ4ZA";
    /// Spec 25 Vector 57's rejected padded form.
    const VECTOR_57_PADDED: &str = "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za====";
    /// The §25.1 fixture identifiers `proposer`, `new member` and `definer`.
    const PROPOSER: &str = "scp:flrkfgy6ehrwj35ay57p36ldffarlcmh2mj7smr7rauyvpreyqfa";
    const NEW_MEMBER: &str = "scp:ykcz3x3dycntc6lkxzbe3nixvd7w5c37riaowlh26lczdnc5vmja";
    const DEFINER: &str = "scp:tfgiiao36zlseo2tzfoi32knfx6topped3qloxcsube5gdvfrqgq";

    fn vector_57_identifier() -> Result<Identifier, Box<dyn std::error::Error>> {
        let bytes = <[u8; 32]>::try_from(hex::decode(VECTOR_57_HEX)?.as_slice())?;
        Ok(Identifier::from_bytes(bytes))
    }

    fn rejected(reason: NonCanonicalReason) -> Result<Identifier, IdentifierError> {
        Err(IdentifierError::NonCanonicalIdentifier { reason })
    }

    #[test]
    fn display_encodes_vector_57() -> TestResult {
        let id = vector_57_identifier()?;
        assert_eq!(id.to_string(), VECTOR_57);
        assert_eq!(id.to_string().len(), 56);
        Ok(())
    }

    #[test]
    fn from_str_decodes_vector_57_and_round_trips() -> TestResult {
        let id = vector_57_identifier()?;
        assert_eq!(VECTOR_57.parse::<Identifier>(), Ok(id));
        for s in [VECTOR_57, PROPOSER, NEW_MEMBER, DEFINER] {
            assert_eq!(s.parse::<Identifier>()?.to_string(), s);
        }
        assert_eq!(Identifier::from_bytes(*id.as_bytes()), id);
        Ok(())
    }

    #[test]
    fn from_str_rejects_vector_57_uppercase_form() {
        assert_eq!(
            VECTOR_57_UPPER.parse::<Identifier>(),
            rejected(NonCanonicalReason::Alphabet)
        );
    }

    #[test]
    fn from_str_rejects_vector_57_padded_form() {
        assert_eq!(
            VECTOR_57_PADDED.parse::<Identifier>(),
            rejected(NonCanonicalReason::Length)
        );
    }

    #[test]
    fn from_str_rejects_did_string() {
        let did = format!("did:{}", &VECTOR_57[4..]);
        assert_eq!(
            did.parse::<Identifier>(),
            rejected(NonCanonicalReason::Prefix)
        );
    }

    #[test]
    fn from_str_rejects_nonzero_trailing_bits() {
        let s = format!("{}b", &VECTOR_57[..VECTOR_57.len() - 1]);
        assert_eq!(
            s.parse::<Identifier>(),
            rejected(NonCanonicalReason::TrailingBits)
        );
    }

    #[test]
    fn from_str_never_trims_whitespace() {
        assert_eq!(
            format!(" {VECTOR_57}").parse::<Identifier>(),
            rejected(NonCanonicalReason::Prefix)
        );
        assert_eq!(
            format!("{VECTOR_57}\n").parse::<Identifier>(),
            rejected(NonCanonicalReason::Length)
        );
    }

    #[test]
    fn zero_is_all_zero_bytes_and_orders_first() -> TestResult {
        assert_eq!(Identifier::ZERO.as_bytes(), &[0u8; 32]);
        assert!(Identifier::ZERO < vector_57_identifier()?);
        let mut low = [0u8; 32];
        low[31] = 0xff;
        let mut high = [0u8; 32];
        high[0] = 0x01;
        // Unsigned byte order: the first byte decides.
        assert!(Identifier::from_bytes(low) < Identifier::from_bytes(high));
        let mut top = [0u8; 32];
        top[0] = 0x80;
        assert!(Identifier::from_bytes(high) < Identifier::from_bytes(top));
        Ok(())
    }

    #[test]
    fn predicate_accepts_vector_57_and_section_25_1_fixtures() {
        for s in [VECTOR_57, PROPOSER, NEW_MEMBER, DEFINER] {
            assert!(is_canonical_identifier_text(s), "{s} must be canonical");
        }
    }

    #[test]
    fn predicate_rejects_vector_57_uppercase_and_padded_forms() {
        assert!(!is_canonical_identifier_text(VECTOR_57_UPPER));
        assert!(!is_canonical_identifier_text(VECTOR_57_PADDED));
    }

    #[test]
    fn predicate_rejects_nonzero_trailing_bits() {
        // `b` encodes 1: the same 32 bytes as the canonical `...a` string.
        let s = format!("{}b", &VECTOR_57[..VECTOR_57.len() - 1]);
        assert!(!is_canonical_identifier_text(&s));
        // `r` encodes 17: the same 32 bytes as the canonical `...q` string.
        let s = format!("{}r", &DEFINER[..DEFINER.len() - 1]);
        assert!(!is_canonical_identifier_text(&s));
    }

    #[test]
    fn predicate_rejects_body_of_51_and_53_chars() {
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
    fn predicate_rejects_wrong_prefix_and_alphabet() {
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
