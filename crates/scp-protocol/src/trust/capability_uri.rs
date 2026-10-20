//! Agent capability URI type with three-authority parser (ADR-041, §7.3.4.1).
//!
//! Parses and validates agent capability URIs in three formats:
//!
//! 1. **Protocol-defined:** `scp:capability:{kebab-case}/v{N}` — reserved prefix
//!    for protocol challenge capabilities.
//! 2. **Identifier-scoped:** `{identifier}:capability:{kebab-case}/v{N}` — custom
//!    capabilities defined under an identifier's authority, where
//!    `{identifier}` is the `03-identity.md` §3.1 text form
//!    (`scp:` plus 52 lowercase base32 characters). A `did:` authority is
//!    rejected with [`CapabilityUriError::NonCanonicalIdentifier`].
//! 3. **System:** `scp:system:{kebab-case}` — protocol feature flags for node
//!    roles, not challenge-testable.
//!
//! # Examples
//!
//! ```
//! use scp_protocol::trust::CapabilityUri;
//!
//! // Protocol capability
//! let uri: CapabilityUri = "scp:capability:prompt-injection-resistance/v1".parse().unwrap();
//! assert_eq!(uri.to_string(), "scp:capability:prompt-injection-resistance/v1");
//!
//! // Identifier-scoped capability
//! let uri: CapabilityUri =
//!     "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za:capability:domain-expertise/v2"
//!         .parse()
//!         .unwrap();
//! assert!(uri.is_identifier_scoped());
//!
//! // System capability
//! let uri: CapabilityUri = "scp:system:relay-operation".parse().unwrap();
//! ```

use std::fmt;
use std::str::FromStr;

use scp_did::is_canonical_identifier_text;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced when parsing a [`CapabilityUri`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityUriError {
    /// The URI string is structurally invalid (missing parts, extra segments).
    #[error("malformed capability URI: {0}")]
    MalformedUri(String),

    /// A name segment does not conform to kebab-case rules (lowercase ASCII
    /// letters and hyphens, no leading/trailing/consecutive hyphens).
    #[error("invalid kebab-case name: {0}")]
    InvalidKebabCase(String),

    /// The version number is invalid (must be a positive integer >= 1).
    #[error("invalid version: {0}")]
    InvalidVersion(String),

    /// The URI prefix is not one of the three recognized authorities.
    #[error("unknown authority: {0}")]
    UnknownAuthority(String),

    /// The authority before `:capability:` is not an identifier in the
    /// canonical text form of `03-identity.md` §3.1 (for example a `did:`
    /// string, an uppercase or padded encoding, or a wrong length).
    #[error("capability URI authority is not a canonical identifier: {0}")]
    NonCanonicalIdentifier(String),
}

// ---------------------------------------------------------------------------
// Kebab-case validation
// ---------------------------------------------------------------------------

/// Validates that `name` conforms to kebab-case: lowercase ASCII letters
/// (`a-z`) and hyphens (`-`), with no leading, trailing, or consecutive
/// hyphens, and at least one letter.
fn validate_kebab_case(name: &str) -> Result<(), CapabilityUriError> {
    if name.is_empty() {
        return Err(CapabilityUriError::InvalidKebabCase(
            "name must not be empty".into(),
        ));
    }

    if name.starts_with('-') || name.ends_with('-') {
        return Err(CapabilityUriError::InvalidKebabCase(format!(
            "'{name}' must not start or end with a hyphen"
        )));
    }

    let mut prev_hyphen = false;
    let mut has_letter = false;
    for ch in name.chars() {
        match ch {
            'a'..='z' => {
                has_letter = true;
                prev_hyphen = false;
            }
            '-' => {
                if prev_hyphen {
                    return Err(CapabilityUriError::InvalidKebabCase(format!(
                        "'{name}' contains consecutive hyphens"
                    )));
                }
                prev_hyphen = true;
            }
            _ => {
                return Err(CapabilityUriError::InvalidKebabCase(format!(
                    "'{name}' contains invalid character '{ch}' (only lowercase ASCII a-z and hyphens allowed)"
                )));
            }
        }
    }

    if !has_letter {
        return Err(CapabilityUriError::InvalidKebabCase(format!(
            "'{name}' must contain at least one letter"
        )));
    }

    Ok(())
}

/// Parses a `"/v{N}"` suffix, returning the version number (must be >= 1).
fn parse_version(s: &str) -> Result<u32, CapabilityUriError> {
    let version_str = s.strip_prefix("/v").ok_or_else(|| {
        CapabilityUriError::MalformedUri(format!("expected '/v{{N}}' version suffix, got '{s}'"))
    })?;

    if version_str.is_empty() {
        return Err(CapabilityUriError::InvalidVersion(
            "version number is empty".into(),
        ));
    }

    let version: u32 = version_str.parse().map_err(|_| {
        CapabilityUriError::InvalidVersion(format!(
            "'{version_str}' is not a valid positive integer"
        ))
    })?;

    if version == 0 {
        return Err(CapabilityUriError::InvalidVersion(
            "version must be >= 1, got 0".into(),
        ));
    }

    Ok(version)
}

// ---------------------------------------------------------------------------
// CapabilityUri
// ---------------------------------------------------------------------------

/// A validated agent capability URI (ADR-041, §7.3.4.1).
///
/// Three authorities are supported:
///
/// - [`Protocol`](CapabilityUri::Protocol): `scp:capability:{name}/v{N}`
/// - [`IdentifierScoped`](CapabilityUri::IdentifierScoped): `{identifier}:capability:{name}/v{N}`
/// - [`System`](CapabilityUri::System): `scp:system:{name}`
///
/// Implements [`FromStr`] for parsing, `Display` for round-trip serialization,
/// and serde `Serialize`/`Deserialize` via the string representation. Parsing
/// accepts only the string `Display` prints back, so each capability has one
/// text form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CapabilityUri {
    /// A protocol-defined challenge capability.
    ///
    /// Format: `scp:capability:{name}/v{version}`
    Protocol {
        /// Kebab-case capability name.
        name: String,
        /// Version number (>= 1).
        version: u32,
    },

    /// An identifier-scoped custom capability.
    ///
    /// Format: `{identifier}:capability:{name}/v{version}`
    IdentifierScoped {
        /// The definer's identifier in the `03-identity.md` §3.1 text form.
        definer: String,
        /// Kebab-case capability name.
        name: String,
        /// Version number (>= 1).
        version: u32,
    },

    /// A system capability (protocol feature flag).
    ///
    /// Format: `scp:system:{name}`
    System {
        /// Kebab-case system capability name.
        name: String,
    },
}

impl FromStr for CapabilityUri {
    type Err = CapabilityUriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_canonical(s)
    }
}

/// The separator between an identifier-scoped URI's authority and its name.
const IDENTIFIER_CAPABILITY_MARKER: &str = ":capability:";

/// Parses any spelling of a capability URI; [`parse_canonical`] then requires
/// the canonical one.
fn parse_any_form(s: &str) -> Result<CapabilityUri, CapabilityUriError> {
    if s.is_empty() {
        return Err(CapabilityUriError::MalformedUri("empty string".into()));
    }

    // Protocol capability: scp:capability:{kebab-case}/v{N}
    if let Some(rest) = s.strip_prefix("scp:capability:") {
        return parse_protocol_capability(rest);
    }

    // System capability: scp:system:{kebab-case}
    if let Some(rest) = s.strip_prefix("scp:system:") {
        return parse_system_capability(rest);
    }

    // Identifier-scoped: {identifier}:capability:{kebab-case}/v{N}. An
    // identifier body holds no ':', so it never matches the two prefixes
    // above.
    if let Some(cap_pos) = s.find(IDENTIFIER_CAPABILITY_MARKER) {
        return parse_identifier_scoped_capability(s, cap_pos);
    }

    // scp: prefix but not capability: or system: — unknown authority
    if let Some(after_scp) = s.strip_prefix("scp:") {
        let authority = after_scp.split(':').next().unwrap_or(after_scp);
        return Err(CapabilityUriError::UnknownAuthority(format!(
            "scp:{authority}"
        )));
    }

    Err(CapabilityUriError::MalformedUri(format!(
        "URI must start with 'scp:', got '{s}'"
    )))
}

/// Parses `s` and accepts it only when it is the text the parsed value
/// prints back, so a non-canonical spelling such as `/v01` or `/v+1` is
/// rejected rather than accepted as a second form of `/v1`.
fn parse_canonical(s: &str) -> Result<CapabilityUri, CapabilityUriError> {
    let parsed = parse_any_form(s)?;
    if parsed.to_string() != s {
        return Err(CapabilityUriError::MalformedUri(format!(
            "'{s}' is not in canonical form (expected '{parsed}')"
        )));
    }
    Ok(parsed)
}

/// Parse the remainder after `scp:capability:`.
fn parse_protocol_capability(rest: &str) -> Result<CapabilityUri, CapabilityUriError> {
    if rest.is_empty() {
        return Err(CapabilityUriError::MalformedUri(
            "missing capability name after 'scp:capability:'".into(),
        ));
    }

    // Find the version separator
    let slash_pos = rest.find('/').ok_or_else(|| {
        CapabilityUriError::MalformedUri(format!(
            "missing version suffix '/v{{N}}' in 'scp:capability:{rest}'"
        ))
    })?;

    let name = &rest[..slash_pos];
    let version_part = &rest[slash_pos..];

    // Check for deeper nesting (extra '/' after the version)
    if version_part.matches('/').count() > 1 {
        return Err(CapabilityUriError::MalformedUri(
            "no deeper nesting permitted after version".into(),
        ));
    }

    validate_kebab_case(name)?;
    let version = parse_version(version_part)?;

    Ok(CapabilityUri::Protocol {
        name: name.to_owned(),
        version,
    })
}

/// Parse the remainder after `scp:system:`.
fn parse_system_capability(rest: &str) -> Result<CapabilityUri, CapabilityUriError> {
    if rest.is_empty() {
        return Err(CapabilityUriError::MalformedUri(
            "missing name after 'scp:system:'".into(),
        ));
    }

    // System capabilities must not have version suffixes or extra segments
    if rest.contains('/') {
        return Err(CapabilityUriError::MalformedUri(
            "system capabilities must not contain '/'".into(),
        ));
    }

    validate_kebab_case(rest)?;

    Ok(CapabilityUri::System {
        name: rest.to_owned(),
    })
}

/// Parses an identifier-scoped capability whose `:capability:` marker
/// starts at byte `cap_pos` of `s`.
fn parse_identifier_scoped_capability(
    s: &str,
    cap_pos: usize,
) -> Result<CapabilityUri, CapabilityUriError> {
    // Format: {identifier}:capability:{kebab-case}/v{N}; the authority is the
    // text before the first `:capability:`. The check is syntactic: the
    // definer is not resolved.
    let definer = &s[..cap_pos];
    let after_cap = &s[cap_pos + IDENTIFIER_CAPABILITY_MARKER.len()..];

    if !is_canonical_identifier_text(definer) {
        return Err(CapabilityUriError::NonCanonicalIdentifier(
            definer.to_owned(),
        ));
    }

    if after_cap.is_empty() {
        return Err(CapabilityUriError::MalformedUri(
            "missing capability name after ':capability:'".into(),
        ));
    }

    // Find the version separator
    let slash_pos = after_cap.find('/').ok_or_else(|| {
        CapabilityUriError::MalformedUri(format!(
            "missing version suffix '/v{{N}}' in identifier-scoped capability '{s}'"
        ))
    })?;

    let name = &after_cap[..slash_pos];
    let version_part = &after_cap[slash_pos..];

    // Check for deeper nesting
    if version_part.matches('/').count() > 1 {
        return Err(CapabilityUriError::MalformedUri(
            "no deeper nesting permitted after version".into(),
        ));
    }

    validate_kebab_case(name)?;
    let version = parse_version(version_part)?;

    Ok(CapabilityUri::IdentifierScoped {
        definer: definer.to_owned(),
        name: name.to_owned(),
        version,
    })
}

impl CapabilityUri {
    /// Returns `true` if this is a [`Protocol`](Self::Protocol) capability.
    #[must_use]
    pub const fn is_protocol(&self) -> bool {
        matches!(self, Self::Protocol { .. })
    }

    /// Returns `true` if this is an [`IdentifierScoped`](Self::IdentifierScoped) capability.
    #[must_use]
    pub const fn is_identifier_scoped(&self) -> bool {
        matches!(self, Self::IdentifierScoped { .. })
    }

    /// Returns `true` if this is a [`System`](Self::System) capability.
    #[must_use]
    pub const fn is_system(&self) -> bool {
        matches!(self, Self::System { .. })
    }

    /// Returns the kebab-case name of this capability URI.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Protocol { name, .. }
            | Self::IdentifierScoped { name, .. }
            | Self::System { name } => name,
        }
    }
}

impl fmt::Display for CapabilityUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol { name, version } => {
                write!(f, "scp:capability:{name}/v{version}")
            }
            Self::IdentifierScoped {
                definer,
                name,
                version,
            } => {
                write!(f, "{definer}:capability:{name}/v{version}")
            }
            Self::System { name } => {
                write!(f, "scp:system:{name}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Serde: serialize/deserialize via string representation
// ---------------------------------------------------------------------------

impl Serialize for CapabilityUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CapabilityUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Spec 25 Vector 57's identifier in the `03-identity.md` §3.1 text form.
    const DEFINER: &str = "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za";
    /// Spec 25 Vector 61's definer, whose last character is `q`.
    const DEFINER_ENDING_Q: &str = "scp:tfgiiao36zlseo2tzfoi32knfx6topped3qloxcsube5gdvfrqgq";

    fn scoped(definer: &str, tail: &str) -> String {
        format!("{definer}:capability:{tail}")
    }

    // -----------------------------------------------------------------------
    // AC 2: Protocol capability parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_protocol_capability() {
        let uri: CapabilityUri = "scp:capability:prompt-injection-resistance/v1"
            .parse()
            .unwrap();
        assert_eq!(
            uri,
            CapabilityUri::Protocol {
                name: "prompt-injection-resistance".into(),
                version: 1,
            }
        );
    }

    #[test]
    fn parse_protocol_capability_higher_version() {
        let uri: CapabilityUri = "scp:capability:schema-validation/v42".parse().unwrap();
        assert_eq!(
            uri,
            CapabilityUri::Protocol {
                name: "schema-validation".into(),
                version: 42,
            }
        );
    }

    // -----------------------------------------------------------------------
    // AC 3: identifier-scoped capability parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_identifier_scoped_capability() {
        let original = scoped(DEFINER, "domain-expertise/v2");
        let uri: CapabilityUri = original.parse().unwrap();
        assert_eq!(
            uri,
            CapabilityUri::IdentifierScoped {
                definer: DEFINER.into(),
                name: "domain-expertise".into(),
                version: 2,
            }
        );
        assert!(uri.is_identifier_scoped());
        assert_eq!(uri.to_string(), original);
    }

    #[test]
    fn accepts_definer_ending_q() {
        let uri: CapabilityUri = scoped(DEFINER_ENDING_Q, "schema-validation/v1")
            .parse()
            .unwrap();
        assert!(matches!(
            uri,
            CapabilityUri::IdentifierScoped { ref definer, .. } if definer == DEFINER_ENDING_Q
        ));
    }

    #[test]
    fn reject_did_authority_is_non_canonical_identifier() {
        for (uri, authority) in [
            (
                "did:dht:z6Mk123:capability:domain-expertise/v2",
                "did:dht:z6Mk123",
            ),
            (
                "did:web:example.com:capability:custom-skill/v1",
                "did:web:example.com",
            ),
        ] {
            let err = uri.parse::<CapabilityUri>().unwrap_err();
            assert_eq!(
                err,
                CapabilityUriError::NonCanonicalIdentifier(authority.into()),
                "{uri}"
            );
        }
    }

    #[test]
    fn reject_uppercase_identifier_authority() {
        let authority = DEFINER.to_ascii_uppercase().replacen("SCP:", "scp:", 1);
        let err = scoped(&authority, "x/v1")
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert_eq!(err, CapabilityUriError::NonCanonicalIdentifier(authority));
    }

    #[test]
    fn reject_padded_identifier_authority() {
        let authority = format!("{DEFINER}====");
        let err = scoped(&authority, "x/v1")
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert_eq!(err, CapabilityUriError::NonCanonicalIdentifier(authority));
    }

    #[test]
    fn reject_identifier_with_nonzero_trailing_bits() {
        // `b` encodes 1, so this decodes to Vector 57's bytes a second way.
        let authority = format!("{}b", &DEFINER[..DEFINER.len() - 1]);
        let err = scoped(&authority, "x/v1")
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert_eq!(err, CapabilityUriError::NonCanonicalIdentifier(authority));
    }

    #[test]
    fn reject_identifier_authority_of_51_and_53_chars() {
        let short = format!("scp:{}", &DEFINER[5..]);
        // Appended after the canonical text, so the 52nd body character is still
        // `q` and only the length rule rejects it.
        let long = format!("{DEFINER}a");
        assert_eq!(short.len(), 4 + 51);
        assert_eq!(long.len(), 4 + 53);
        for authority in [short, long] {
            let err = scoped(&authority, "x/v1")
                .parse::<CapabilityUri>()
                .unwrap_err();
            assert_eq!(err, CapabilityUriError::NonCanonicalIdentifier(authority));
        }
    }

    #[test]
    fn identifier_beginning_with_capability_parses_as_identifier_scoped() {
        // A canonical identifier whose base32 body starts with "capability".
        let definer = format!("scp:capability{}", &DEFINER[14..]);
        assert_eq!(definer.len(), 56);
        let uri: CapabilityUri = scoped(&definer, "x/v1").parse().unwrap();
        assert_eq!(
            uri,
            CapabilityUri::IdentifierScoped {
                definer,
                name: "x".into(),
                version: 1,
            }
        );
    }

    #[test]
    fn reject_non_canonical_version_form() {
        for tail in ["/v01", "/v+1"] {
            for uri in [
                format!("scp:capability:name{tail}"),
                scoped(DEFINER, &format!("name{tail}")),
            ] {
                let err = uri.parse::<CapabilityUri>().unwrap_err();
                assert!(
                    matches!(err, CapabilityUriError::MalformedUri(_)),
                    "{uri} must be MalformedUri, got {err:?}"
                );
            }
        }
    }

    #[test]
    fn accepts_two_digit_version() {
        for uri in [
            "scp:capability:name/v10".to_owned(),
            scoped(DEFINER, "name/v10"),
        ] {
            let parsed: CapabilityUri = uri.parse().unwrap();
            assert_eq!(parsed.to_string(), uri);
        }
    }

    // -----------------------------------------------------------------------
    // AC 4: System capability parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_system_capability() {
        let uri: CapabilityUri = "scp:system:relay-operation".parse().unwrap();
        assert_eq!(
            uri,
            CapabilityUri::System {
                name: "relay-operation".into(),
            }
        );
    }

    #[test]
    fn parse_system_capability_single_word() {
        // System names can be single words in kebab-case
        // Actually kebab-case requires at least one letter, single words are fine
        let uri: CapabilityUri = "scp:system:relay".parse().unwrap();
        assert_eq!(
            uri,
            CapabilityUri::System {
                name: "relay".into(),
            }
        );
    }

    // -----------------------------------------------------------------------
    // AC 5: Reject uppercase (InvalidKebabCase)
    // -----------------------------------------------------------------------

    #[test]
    fn reject_uppercase_protocol() {
        let err = "scp:capability:UPPERCASE/v1"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(
            matches!(err, CapabilityUriError::InvalidKebabCase(_)),
            "expected InvalidKebabCase, got {err:?}"
        );
    }

    #[test]
    fn reject_mixed_case() {
        let err = "scp:capability:camelCase/v1"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::InvalidKebabCase(_)));
    }

    #[test]
    fn reject_uppercase_system() {
        let err = "scp:system:RelayOperation"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::InvalidKebabCase(_)));
    }

    #[test]
    fn reject_digits_in_name() {
        let err = "scp:capability:test123/v1"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::InvalidKebabCase(_)));
    }

    #[test]
    fn reject_underscore_in_name() {
        let err = "scp:capability:test_name/v1"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::InvalidKebabCase(_)));
    }

    #[test]
    fn reject_leading_hyphen() {
        let err = "scp:capability:-leading/v1"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::InvalidKebabCase(_)));
    }

    #[test]
    fn reject_trailing_hyphen() {
        let err = "scp:capability:trailing-/v1"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::InvalidKebabCase(_)));
    }

    #[test]
    fn reject_consecutive_hyphens() {
        let err = "scp:capability:double--hyphen/v1"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::InvalidKebabCase(_)));
    }

    // -----------------------------------------------------------------------
    // AC 6: Reject version 0 (InvalidVersion)
    // -----------------------------------------------------------------------

    #[test]
    fn reject_version_zero() {
        let err = "scp:capability:name/v0"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(
            matches!(err, CapabilityUriError::InvalidVersion(_)),
            "expected InvalidVersion, got {err:?}"
        );
    }

    #[test]
    fn reject_negative_version() {
        // Negative won't parse as u32
        let err = "scp:capability:name/v-1"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::InvalidVersion(_)));
    }

    #[test]
    fn reject_non_numeric_version() {
        let err = "scp:capability:name/vabc"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::InvalidVersion(_)));
    }

    // -----------------------------------------------------------------------
    // AC 7: Missing version for capability URIs (MalformedUri)
    // -----------------------------------------------------------------------

    #[test]
    fn reject_missing_version_protocol() {
        let err = "scp:capability:name".parse::<CapabilityUri>().unwrap_err();
        assert!(
            matches!(err, CapabilityUriError::MalformedUri(_)),
            "expected MalformedUri, got {err:?}"
        );
    }

    #[test]
    fn reject_missing_version_identifier_scoped() {
        let err = scoped(DEFINER, "name")
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::MalformedUri(_)));
    }

    // -----------------------------------------------------------------------
    // AC 8: Unknown authority (UnknownAuthority)
    // -----------------------------------------------------------------------

    #[test]
    fn reject_unknown_authority() {
        let err = "scp:unknown:name".parse::<CapabilityUri>().unwrap_err();
        assert!(
            matches!(err, CapabilityUriError::UnknownAuthority(_)),
            "expected UnknownAuthority, got {err:?}"
        );
    }

    #[test]
    fn reject_unknown_authority_foo() {
        let err = "scp:foo:bar/v1".parse::<CapabilityUri>().unwrap_err();
        assert!(matches!(err, CapabilityUriError::UnknownAuthority(_)));
    }

    // -----------------------------------------------------------------------
    // AC 9: No deeper nesting (MalformedUri)
    // -----------------------------------------------------------------------

    #[test]
    fn reject_deeper_nesting_protocol() {
        let err = "scp:capability:name/v1/extra"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(
            matches!(err, CapabilityUriError::MalformedUri(_)),
            "expected MalformedUri, got {err:?}"
        );
    }

    #[test]
    fn reject_deeper_nesting_identifier_scoped() {
        let err = scoped(DEFINER, "name/v1/extra")
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::MalformedUri(_)));
    }

    #[test]
    fn reject_slash_in_system() {
        let err = "scp:system:relay/operation"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::MalformedUri(_)));
    }

    // -----------------------------------------------------------------------
    // AC 10: Display round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn display_roundtrip_protocol() {
        let original = "scp:capability:prompt-injection-resistance/v1";
        let uri: CapabilityUri = original.parse().unwrap();
        assert_eq!(uri.to_string(), original);
    }

    #[test]
    fn display_roundtrip_identifier_scoped() {
        let original = scoped(DEFINER, "domain-expertise/v2");
        let uri: CapabilityUri = original.parse().unwrap();
        assert_eq!(uri.to_string(), original);
    }

    #[test]
    fn display_roundtrip_system() {
        let original = "scp:system:relay-operation";
        let uri: CapabilityUri = original.parse().unwrap();
        assert_eq!(uri.to_string(), original);
    }

    #[test]
    fn display_roundtrip_all_protocol_registry_capabilities() {
        // All 27 protocol capabilities from §7.3.4.3
        let uris = [
            "scp:capability:prompt-injection-resistance/v1",
            "scp:capability:content-safety/v1",
            "scp:capability:privacy-compliance/v1",
            "scp:capability:credential-handling/v1",
            "scp:capability:schema-validation/v1",
            "scp:capability:outlet-schema-compliance/v1",
            "scp:capability:output-format-compliance/v1",
            "scp:capability:rate-limit-compliance/v1",
            "scp:capability:instruction-adherence/v1",
            "scp:capability:context-policy-adherence/v1",
            "scp:capability:graceful-degradation/v1",
            "scp:capability:latency-compliance/v1",
            "scp:capability:idempotency/v1",
            "scp:capability:multilingual/v1",
            "scp:capability:spending-compliance/v1",
            "scp:capability:cost-awareness/v1",
            "scp:capability:logical-reasoning/v1",
            "scp:capability:mathematical-reasoning/v1",
            "scp:capability:causal-reasoning/v1",
            "scp:capability:code-generation/v1",
            "scp:capability:code-review/v1",
            "scp:capability:context-recall/v1",
            "scp:capability:instruction-retention/v1",
            "scp:capability:bias-resistance/v1",
            "scp:capability:viewpoint-diversity/v1",
            "scp:capability:factual-accuracy/v1",
            "scp:capability:hallucination-resistance/v1",
            "scp:capability:source-attribution/v1",
        ];
        for original in uris {
            let uri: CapabilityUri = original.parse().unwrap();
            assert_eq!(
                uri.to_string(),
                original,
                "round-trip failed for {original}"
            );
        }
    }

    #[test]
    fn display_roundtrip_all_system_capabilities() {
        // All 4 system capabilities from §7.3.4.3
        let uris = [
            "scp:system:mls-group-management",
            "scp:system:key-rotation",
            "scp:system:governance-participation",
            "scp:system:relay-operation",
        ];
        for original in uris {
            let uri: CapabilityUri = original.parse().unwrap();
            assert_eq!(
                uri.to_string(),
                original,
                "round-trip failed for {original}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // AC 11: Derive traits
    // -----------------------------------------------------------------------

    #[test]
    fn capability_uri_is_clone() {
        let uri: CapabilityUri = "scp:capability:test/v1".parse().unwrap();
        let cloned = uri.clone();
        assert_eq!(uri, cloned);
    }

    #[test]
    fn capability_uri_is_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let uri: CapabilityUri = "scp:capability:test/v1".parse().unwrap();
        set.insert(uri.clone());
        set.insert(uri);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn capability_uri_debug() {
        let uri: CapabilityUri = "scp:capability:test/v1".parse().unwrap();
        let debug = format!("{uri:?}");
        assert!(debug.contains("Protocol"));
        assert!(debug.contains("test"));
    }

    // -----------------------------------------------------------------------
    // AC 11: Serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn serde_roundtrip_protocol() {
        let uri: CapabilityUri = "scp:capability:test/v1".parse().unwrap();
        let json = serde_json::to_string(&uri).unwrap();
        assert_eq!(json, "\"scp:capability:test/v1\"");
        let deserialized: CapabilityUri = serde_json::from_str(&json).unwrap();
        assert_eq!(uri, deserialized);
    }

    #[test]
    fn serde_roundtrip_identifier_scoped() {
        let uri: CapabilityUri = scoped(DEFINER, "skill/v3").parse().unwrap();
        let json = serde_json::to_string(&uri).unwrap();
        let deserialized: CapabilityUri = serde_json::from_str(&json).unwrap();
        assert_eq!(uri, deserialized);
    }

    #[test]
    fn serde_roundtrip_system() {
        let uri: CapabilityUri = "scp:system:relay-operation".parse().unwrap();
        let json = serde_json::to_string(&uri).unwrap();
        let deserialized: CapabilityUri = serde_json::from_str(&json).unwrap();
        assert_eq!(uri, deserialized);
    }

    #[test]
    fn serde_rejects_invalid_uri() {
        let result: Result<CapabilityUri, _> = serde_json::from_str("\"scp:unknown:foo\"");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // AC 12 & 13: Coverage for all authority types and all error variants
    // -----------------------------------------------------------------------

    #[test]
    fn all_error_variants_reachable() {
        // MalformedUri
        assert!(matches!(
            "scp:capability:name".parse::<CapabilityUri>().unwrap_err(),
            CapabilityUriError::MalformedUri(_)
        ));

        // InvalidKebabCase
        assert!(matches!(
            "scp:capability:UPPER/v1"
                .parse::<CapabilityUri>()
                .unwrap_err(),
            CapabilityUriError::InvalidKebabCase(_)
        ));

        // InvalidVersion
        assert!(matches!(
            "scp:capability:name/v0"
                .parse::<CapabilityUri>()
                .unwrap_err(),
            CapabilityUriError::InvalidVersion(_)
        ));

        // UnknownAuthority
        assert!(matches!(
            "scp:unknown:name".parse::<CapabilityUri>().unwrap_err(),
            CapabilityUriError::UnknownAuthority(_)
        ));

        // NonCanonicalIdentifier
        assert!(matches!(
            "did:dht:z6Mk123:capability:name/v1"
                .parse::<CapabilityUri>()
                .unwrap_err(),
            CapabilityUriError::NonCanonicalIdentifier(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn reject_empty_string() {
        let err = "".parse::<CapabilityUri>().unwrap_err();
        assert!(matches!(err, CapabilityUriError::MalformedUri(_)));
    }

    #[test]
    fn reject_random_string() {
        let err = "not-a-uri".parse::<CapabilityUri>().unwrap_err();
        assert!(matches!(err, CapabilityUriError::MalformedUri(_)));
    }

    #[test]
    fn reject_http_uri() {
        let err = "http://example.com".parse::<CapabilityUri>().unwrap_err();
        assert!(matches!(err, CapabilityUriError::MalformedUri(_)));
    }

    #[test]
    fn reject_empty_name_protocol() {
        let err = "scp:capability:/v1".parse::<CapabilityUri>().unwrap_err();
        assert!(matches!(err, CapabilityUriError::InvalidKebabCase(_)));
    }

    #[test]
    fn reject_empty_version_number() {
        let err = "scp:capability:name/v"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::InvalidVersion(_)));
    }

    #[test]
    fn reject_did_without_capability_segment() {
        let err = "did:dht:z6Mk123:name/v1"
            .parse::<CapabilityUri>()
            .unwrap_err();
        assert!(matches!(err, CapabilityUriError::MalformedUri(_)));
    }

    #[test]
    fn reject_did_authority_with_empty_method_or_id() {
        for (uri, authority) in [
            ("did::z6Mk123:capability:name/v1", "did::z6Mk123"),
            ("did:dht::capability:name/v1", "did:dht:"),
        ] {
            let err = uri.parse::<CapabilityUri>().unwrap_err();
            assert_eq!(
                err,
                CapabilityUriError::NonCanonicalIdentifier(authority.into())
            );
        }
    }

    #[test]
    fn eq_different_variants_not_equal() {
        let protocol: CapabilityUri = "scp:capability:test/v1".parse().unwrap();
        let system: CapabilityUri = "scp:system:test".parse().unwrap();
        assert_ne!(protocol, system);
    }

    #[test]
    fn eq_different_versions_not_equal() {
        let v1: CapabilityUri = "scp:capability:test/v1".parse().unwrap();
        let v2: CapabilityUri = "scp:capability:test/v2".parse().unwrap();
        assert_ne!(v1, v2);
    }
}
