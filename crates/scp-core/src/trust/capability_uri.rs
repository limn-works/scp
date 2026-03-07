//! Agent capability URI parsing and validation (ADR-041, §7.3.4.1).
//!
//! Agent capabilities use a structured URI format with three authorities:
//!
//! 1. **Protocol-defined challenge capabilities** (`scp:capability:{kebab-case}/v{N}`):
//!    Reserved prefix. SDKs MUST reject any `scp:capability:*` URI not present
//!    in the signed protocol registry.
//!
//! 2. **DID-scoped custom capabilities** (`did:{method}:{id}:capability:{kebab-case}/v{N}`):
//!    Anyone can define capabilities under their own DID. Authority derives
//!    from the definer's identity.
//!
//! 3. **System capabilities** (`scp:system:{kebab-case}`):
//!    Protocol-level node roles. Not challenge-testable.
//!
//! # Important
//!
//! This type is distinct from [`crate::crypto::ucan::capability::CapabilityUri`],
//! which represents UCAN context capabilities (`scp:ctx:{id}/{resource}:{action}`).
//! This type represents agent capability URIs used in challenge-response
//! verification, DID document capability advertising, and context admission.
//!
//! See ADR-041 in `.docs/adrs/phase-4.md` and §7.3.4.1 in
//! `.docs/specs/07-trust-validation-and-capabilities.md`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CapabilityUriError
// ---------------------------------------------------------------------------

/// Errors produced when parsing or validating an agent capability URI.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityUriError {
    /// The URI string is malformed (missing separators, extra nesting, etc.).
    #[error("malformed capability URI: {0}")]
    MalformedUri(String),

    /// The capability name is not valid kebab-case (lowercase ASCII + hyphens).
    #[error("invalid kebab-case name: {0}")]
    InvalidKebabCase(String),

    /// The version number is invalid (must be a positive integer >= 1).
    #[error("invalid version: {0}")]
    InvalidVersion(String),

    /// The URI authority prefix is not recognized.
    #[error("unknown URI authority: {0}")]
    UnknownAuthority(String),

    /// The URI uses the reserved `scp:capability:*` prefix but is not in
    /// the protocol registry.
    #[error("unknown protocol capability: {0}")]
    UnknownProtocolCapability(String),
}

// ---------------------------------------------------------------------------
// AgentCapabilityUri
// ---------------------------------------------------------------------------

/// A parsed and validated agent capability URI (ADR-041).
///
/// Three variants correspond to the three URI authorities:
///
/// - [`Protocol`](AgentCapabilityUri::Protocol): `scp:capability:{name}/v{version}`
/// - [`DidScoped`](AgentCapabilityUri::DidScoped): `did:{method}:{id}:capability:{name}/v{version}`
/// - [`System`](AgentCapabilityUri::System): `scp:system:{name}`
///
/// All names must be valid kebab-case (lowercase ASCII letters, digits, and
/// hyphens; must not start or end with a hyphen).
///
/// # Serialization
///
/// Serializes to/from the canonical URI string representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AgentCapabilityUri {
    /// A protocol-defined challenge capability.
    ///
    /// URI format: `scp:capability:{name}/v{version}`
    Protocol {
        /// Kebab-case capability name (e.g., `"prompt-injection-resistance"`).
        name: String,
        /// Version number (must be >= 1).
        version: u32,
    },

    /// A DID-scoped custom capability.
    ///
    /// URI format: `did:{method}:{id}:capability:{name}/v{version}`
    DidScoped {
        /// The definer's DID (e.g., `"did:dht:z6Mk123"`).
        did: String,
        /// Kebab-case capability name.
        name: String,
        /// Version number (must be >= 1).
        version: u32,
    },

    /// A system capability (protocol-level node role).
    ///
    /// URI format: `scp:system:{name}`
    System {
        /// Kebab-case system capability name (e.g., `"relay-operation"`).
        name: String,
    },
}

impl AgentCapabilityUri {
    /// Returns the kebab-case capability name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Protocol { name, .. } | Self::DidScoped { name, .. } | Self::System { name } => {
                name
            }
        }
    }

    /// Returns the version number, or `None` for system capabilities.
    #[must_use]
    pub const fn version(&self) -> Option<u32> {
        match self {
            Self::Protocol { version, .. } | Self::DidScoped { version, .. } => Some(*version),
            Self::System { .. } => None,
        }
    }

    /// Returns `true` if this is a protocol-defined capability.
    #[must_use]
    pub const fn is_protocol(&self) -> bool {
        matches!(self, Self::Protocol { .. })
    }

    /// Returns `true` if this is a DID-scoped custom capability.
    #[must_use]
    pub const fn is_did_scoped(&self) -> bool {
        matches!(self, Self::DidScoped { .. })
    }

    /// Returns `true` if this is a system capability.
    #[must_use]
    pub const fn is_system(&self) -> bool {
        matches!(self, Self::System { .. })
    }

    /// Convenience constructor for protocol capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityUriError::InvalidKebabCase`] if the name is not
    /// valid kebab-case, or [`CapabilityUriError::InvalidVersion`] if the
    /// version is 0.
    pub fn protocol(name: impl Into<String>, version: u32) -> Result<Self, CapabilityUriError> {
        let name = name.into();
        validate_kebab_case(&name)?;
        if version == 0 {
            return Err(CapabilityUriError::InvalidVersion(
                "version must be >= 1".to_owned(),
            ));
        }
        Ok(Self::Protocol { name, version })
    }

    /// Convenience constructor for DID-scoped capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityUriError::InvalidKebabCase`] if the name is not
    /// valid kebab-case, [`CapabilityUriError::InvalidVersion`] if the
    /// version is 0, or [`CapabilityUriError::MalformedUri`] if the DID is
    /// empty.
    pub fn did_scoped(
        did: impl Into<String>,
        name: impl Into<String>,
        version: u32,
    ) -> Result<Self, CapabilityUriError> {
        let did = did.into();
        let name = name.into();
        if did.is_empty() {
            return Err(CapabilityUriError::MalformedUri(
                "DID must not be empty".to_owned(),
            ));
        }
        validate_kebab_case(&name)?;
        if version == 0 {
            return Err(CapabilityUriError::InvalidVersion(
                "version must be >= 1".to_owned(),
            ));
        }
        Ok(Self::DidScoped { did, name, version })
    }

    /// Convenience constructor for system capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityUriError::InvalidKebabCase`] if the name is not
    /// valid kebab-case.
    pub fn system(name: impl Into<String>) -> Result<Self, CapabilityUriError> {
        let name = name.into();
        validate_kebab_case(&name)?;
        Ok(Self::System { name })
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validates that a string is valid kebab-case.
///
/// Valid kebab-case: lowercase ASCII letters, digits, and hyphens. Must not
/// start or end with a hyphen. Must not contain consecutive hyphens. Must
/// not be empty.
fn validate_kebab_case(s: &str) -> Result<(), CapabilityUriError> {
    if s.is_empty() {
        return Err(CapabilityUriError::InvalidKebabCase(
            "name must not be empty".to_owned(),
        ));
    }

    if s.starts_with('-') || s.ends_with('-') {
        return Err(CapabilityUriError::InvalidKebabCase(format!(
            "'{s}' must not start or end with a hyphen"
        )));
    }

    if s.contains("--") {
        return Err(CapabilityUriError::InvalidKebabCase(format!(
            "'{s}' must not contain consecutive hyphens"
        )));
    }

    for ch in s.chars() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '-' {
            return Err(CapabilityUriError::InvalidKebabCase(format!(
                "'{s}' contains invalid character '{ch}' (must be lowercase ASCII, digits, or hyphens)"
            )));
        }
    }

    Ok(())
}

/// Parses a version suffix like `/v1` and returns the version number.
fn parse_version(s: &str) -> Result<u32, CapabilityUriError> {
    let version_str = s.strip_prefix("/v").ok_or_else(|| {
        CapabilityUriError::MalformedUri(format!("expected '/v{{N}}' version suffix, got '{s}'"))
    })?;

    if version_str.is_empty() {
        return Err(CapabilityUriError::InvalidVersion(
            "version number is empty".to_owned(),
        ));
    }

    let version: u32 = version_str.parse().map_err(|_| {
        CapabilityUriError::InvalidVersion(format!("'{version_str}' is not a valid version number"))
    })?;

    if version == 0 {
        return Err(CapabilityUriError::InvalidVersion(
            "version must be >= 1".to_owned(),
        ));
    }

    Ok(version)
}

// ---------------------------------------------------------------------------
// FromStr
// ---------------------------------------------------------------------------

impl FromStr for AgentCapabilityUri {
    type Err = CapabilityUriError;

    /// Parses an agent capability URI from its string representation.
    ///
    /// # Errors
    ///
    /// Returns a specific [`CapabilityUriError`] variant for each failure mode.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("scp:capability:") {
            // Protocol capability: scp:capability:{name}/v{N}
            // Reject deeper nesting: no additional '/' after the version.
            let (name_part, version_part) = rest.split_once('/').ok_or_else(|| {
                CapabilityUriError::MalformedUri(format!(
                    "missing version suffix in protocol capability URI '{s}'"
                ))
            })?;

            // Check for deeper nesting (extra '/' in version_part).
            if version_part.contains('/') {
                return Err(CapabilityUriError::MalformedUri(format!(
                    "deeper nesting not permitted in '{s}'"
                )));
            }

            validate_kebab_case(name_part)?;
            let version = parse_version(&format!("/{version_part}"))?;

            Ok(Self::Protocol {
                name: name_part.to_owned(),
                version,
            })
        } else if let Some(rest) = s.strip_prefix("scp:system:") {
            // System capability: scp:system:{name}
            if rest.is_empty() {
                return Err(CapabilityUriError::MalformedUri(
                    "empty system capability name".to_owned(),
                ));
            }
            // System capabilities have no version — reject '/' in name.
            if rest.contains('/') {
                return Err(CapabilityUriError::MalformedUri(format!(
                    "system capabilities do not have versions: '{s}'"
                )));
            }
            validate_kebab_case(rest)?;
            Ok(Self::System {
                name: rest.to_owned(),
            })
        } else if s.starts_with("scp:") {
            // Unknown scp: authority.
            let authority = s
                .strip_prefix("scp:")
                .and_then(|r| r.split_once(':').map(|(a, _)| a))
                .unwrap_or("unknown");
            Err(CapabilityUriError::UnknownAuthority(format!(
                "unknown SCP authority 'scp:{authority}:' in '{s}'"
            )))
        } else if s.starts_with("did:") {
            // DID-scoped: did:{method}:{id}:capability:{name}/v{N}
            // Find ":capability:" in the string.
            let cap_marker = ":capability:";
            let cap_idx = s.find(cap_marker).ok_or_else(|| {
                CapabilityUriError::MalformedUri(format!(
                    "DID-scoped URI missing ':capability:' segment in '{s}'"
                ))
            })?;

            let did = &s[..cap_idx];
            let after_cap = &s[cap_idx + cap_marker.len()..];

            if did.is_empty() || !did.starts_with("did:") {
                return Err(CapabilityUriError::MalformedUri(format!(
                    "invalid DID prefix in '{s}'"
                )));
            }

            // Validate minimal DID structure: did:{method}:{id}
            let did_parts: Vec<&str> = did.split(':').collect();
            if did_parts.len() < 3 || did_parts[1].is_empty() || did_parts[2].is_empty() {
                return Err(CapabilityUriError::MalformedUri(format!(
                    "invalid DID structure in '{s}'"
                )));
            }

            // Parse name/version from after_cap.
            let (name_part, version_part) = after_cap.split_once('/').ok_or_else(|| {
                CapabilityUriError::MalformedUri(format!(
                    "missing version suffix in DID-scoped capability URI '{s}'"
                ))
            })?;

            // Check for deeper nesting.
            if version_part.contains('/') {
                return Err(CapabilityUriError::MalformedUri(format!(
                    "deeper nesting not permitted in '{s}'"
                )));
            }

            validate_kebab_case(name_part)?;
            let version = parse_version(&format!("/{version_part}"))?;

            Ok(Self::DidScoped {
                did: did.to_owned(),
                name: name_part.to_owned(),
                version,
            })
        } else {
            Err(CapabilityUriError::UnknownAuthority(format!(
                "unrecognized URI scheme in '{s}'"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl fmt::Display for AgentCapabilityUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol { name, version } => {
                write!(f, "scp:capability:{name}/v{version}")
            }
            Self::DidScoped { did, name, version } => {
                write!(f, "{did}:capability:{name}/v{version}")
            }
            Self::System { name } => {
                write!(f, "scp:system:{name}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Serialize / Deserialize (via string representation)
// ---------------------------------------------------------------------------

impl Serialize for AgentCapabilityUri {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AgentCapabilityUri {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
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

    // -----------------------------------------------------------------------
    // Protocol capability parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_protocol_capability() {
        let uri: AgentCapabilityUri = "scp:capability:prompt-injection-resistance/v1"
            .parse()
            .unwrap();
        assert_eq!(
            uri,
            AgentCapabilityUri::Protocol {
                name: "prompt-injection-resistance".to_owned(),
                version: 1,
            }
        );
        assert!(uri.is_protocol());
        assert!(!uri.is_did_scoped());
        assert!(!uri.is_system());
        assert_eq!(uri.name(), "prompt-injection-resistance");
        assert_eq!(uri.version(), Some(1));
    }

    #[test]
    fn parse_protocol_capability_higher_version() {
        let uri: AgentCapabilityUri = "scp:capability:schema-validation/v3".parse().unwrap();
        assert_eq!(
            uri,
            AgentCapabilityUri::Protocol {
                name: "schema-validation".to_owned(),
                version: 3,
            }
        );
    }

    // -----------------------------------------------------------------------
    // DID-scoped capability parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_did_scoped_capability() {
        let uri: AgentCapabilityUri = "did:dht:z6Mk123:capability:domain-expertise/v2"
            .parse()
            .unwrap();
        assert_eq!(
            uri,
            AgentCapabilityUri::DidScoped {
                did: "did:dht:z6Mk123".to_owned(),
                name: "domain-expertise".to_owned(),
                version: 2,
            }
        );
        assert!(uri.is_did_scoped());
        assert_eq!(uri.name(), "domain-expertise");
        assert_eq!(uri.version(), Some(2));
    }

    #[test]
    fn parse_did_web_scoped_capability() {
        let uri: AgentCapabilityUri = "did:web:example.com:capability:custom-check/v1"
            .parse()
            .unwrap();
        assert_eq!(
            uri,
            AgentCapabilityUri::DidScoped {
                did: "did:web:example.com".to_owned(),
                name: "custom-check".to_owned(),
                version: 1,
            }
        );
    }

    // -----------------------------------------------------------------------
    // System capability parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_system_capability() {
        let uri: AgentCapabilityUri = "scp:system:relay-operation".parse().unwrap();
        assert_eq!(
            uri,
            AgentCapabilityUri::System {
                name: "relay-operation".to_owned(),
            }
        );
        assert!(uri.is_system());
        assert_eq!(uri.name(), "relay-operation");
        assert_eq!(uri.version(), None);
    }

    // -----------------------------------------------------------------------
    // Error cases
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_uppercase_name() {
        let result: Result<AgentCapabilityUri, _> = "scp:capability:UPPERCASE/v1".parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityUriError::InvalidKebabCase(_) => {}
            other => panic!("expected InvalidKebabCase, got {other:?}"),
        }
    }

    #[test]
    fn rejects_version_zero() {
        let result: Result<AgentCapabilityUri, _> = "scp:capability:name/v0".parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityUriError::InvalidVersion(_) => {}
            other => panic!("expected InvalidVersion, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_version() {
        let result: Result<AgentCapabilityUri, _> = "scp:capability:name".parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityUriError::MalformedUri(_) => {}
            other => panic!("expected MalformedUri, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_scp_authority() {
        let result: Result<AgentCapabilityUri, _> = "scp:unknown:name".parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityUriError::UnknownAuthority(_) => {}
            other => panic!("expected UnknownAuthority, got {other:?}"),
        }
    }

    #[test]
    fn rejects_deeper_nesting() {
        let result: Result<AgentCapabilityUri, _> = "scp:capability:name/v1/extra".parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityUriError::MalformedUri(_) => {}
            other => panic!("expected MalformedUri, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_string() {
        let result: Result<AgentCapabilityUri, _> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn rejects_name_starting_with_hyphen() {
        let result: Result<AgentCapabilityUri, _> = "scp:capability:-name/v1".parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityUriError::InvalidKebabCase(_) => {}
            other => panic!("expected InvalidKebabCase, got {other:?}"),
        }
    }

    #[test]
    fn rejects_name_ending_with_hyphen() {
        let result: Result<AgentCapabilityUri, _> = "scp:capability:name-/v1".parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityUriError::InvalidKebabCase(_) => {}
            other => panic!("expected InvalidKebabCase, got {other:?}"),
        }
    }

    #[test]
    fn rejects_consecutive_hyphens() {
        let result: Result<AgentCapabilityUri, _> = "scp:capability:bad--name/v1".parse();
        assert!(result.is_err());
    }

    #[test]
    fn rejects_system_with_version() {
        let result: Result<AgentCapabilityUri, _> = "scp:system:relay-operation/v1".parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityUriError::MalformedUri(_) => {}
            other => panic!("expected MalformedUri, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unrecognized_scheme() {
        let result: Result<AgentCapabilityUri, _> = "http://example.com/cap".parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityUriError::UnknownAuthority(_) => {}
            other => panic!("expected UnknownAuthority, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Display round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn display_roundtrip_protocol() {
        let uri_str = "scp:capability:prompt-injection-resistance/v1";
        let parsed: AgentCapabilityUri = uri_str.parse().unwrap();
        assert_eq!(parsed.to_string(), uri_str);
    }

    #[test]
    fn display_roundtrip_did_scoped() {
        let uri_str = "did:dht:z6Mk123:capability:domain-expertise/v2";
        let parsed: AgentCapabilityUri = uri_str.parse().unwrap();
        assert_eq!(parsed.to_string(), uri_str);
    }

    #[test]
    fn display_roundtrip_system() {
        let uri_str = "scp:system:relay-operation";
        let parsed: AgentCapabilityUri = uri_str.parse().unwrap();
        assert_eq!(parsed.to_string(), uri_str);
    }

    // -----------------------------------------------------------------------
    // Serialize / Deserialize
    // -----------------------------------------------------------------------

    #[test]
    fn serde_roundtrip_protocol() {
        let uri = AgentCapabilityUri::Protocol {
            name: "schema-validation".to_owned(),
            version: 1,
        };
        let json = serde_json::to_string(&uri).unwrap();
        assert_eq!(json, "\"scp:capability:schema-validation/v1\"");
        let deserialized: AgentCapabilityUri = serde_json::from_str(&json).unwrap();
        assert_eq!(uri, deserialized);
    }

    #[test]
    fn serde_roundtrip_did_scoped() {
        let uri = AgentCapabilityUri::DidScoped {
            did: "did:dht:z6Mk123".to_owned(),
            name: "custom".to_owned(),
            version: 1,
        };
        let json = serde_json::to_string(&uri).unwrap();
        let deserialized: AgentCapabilityUri = serde_json::from_str(&json).unwrap();
        assert_eq!(uri, deserialized);
    }

    #[test]
    fn serde_roundtrip_system() {
        let uri = AgentCapabilityUri::System {
            name: "relay-operation".to_owned(),
        };
        let json = serde_json::to_string(&uri).unwrap();
        assert_eq!(json, "\"scp:system:relay-operation\"");
        let deserialized: AgentCapabilityUri = serde_json::from_str(&json).unwrap();
        assert_eq!(uri, deserialized);
    }

    // -----------------------------------------------------------------------
    // Hash / Eq
    // -----------------------------------------------------------------------

    #[test]
    fn hash_set_dedup() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(
            "scp:capability:schema-validation/v1"
                .parse::<AgentCapabilityUri>()
                .unwrap(),
        );
        set.insert(
            "scp:capability:schema-validation/v1"
                .parse::<AgentCapabilityUri>()
                .unwrap(),
        );
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn different_versions_are_distinct() {
        let v1: AgentCapabilityUri = "scp:capability:schema-validation/v1".parse().unwrap();
        let v2: AgentCapabilityUri = "scp:capability:schema-validation/v2".parse().unwrap();
        assert_ne!(v1, v2);
    }

    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    #[test]
    fn protocol_constructor() {
        let uri = AgentCapabilityUri::protocol("prompt-injection-resistance", 1).unwrap();
        assert_eq!(
            uri.to_string(),
            "scp:capability:prompt-injection-resistance/v1"
        );
    }

    #[test]
    fn did_scoped_constructor() {
        let uri = AgentCapabilityUri::did_scoped("did:dht:z6Mk123", "custom", 1).unwrap();
        assert_eq!(uri.to_string(), "did:dht:z6Mk123:capability:custom/v1");
    }

    #[test]
    fn system_constructor() {
        let uri = AgentCapabilityUri::system("relay-operation").unwrap();
        assert_eq!(uri.to_string(), "scp:system:relay-operation");
    }

    #[test]
    fn constructor_rejects_invalid_name() {
        assert!(AgentCapabilityUri::protocol("BAD", 1).is_err());
        assert!(AgentCapabilityUri::did_scoped("did:dht:z", "BAD", 1).is_err());
        assert!(AgentCapabilityUri::system("BAD").is_err());
    }

    #[test]
    fn constructor_rejects_version_zero() {
        assert!(AgentCapabilityUri::protocol("name", 0).is_err());
        assert!(AgentCapabilityUri::did_scoped("did:dht:z", "name", 0).is_err());
    }

    // -----------------------------------------------------------------------
    // Name with digits
    // -----------------------------------------------------------------------

    #[test]
    fn accepts_name_with_digits() {
        let uri: AgentCapabilityUri = "scp:capability:check-v2-compat/v1".parse().unwrap();
        assert_eq!(uri.name(), "check-v2-compat");
    }
}
