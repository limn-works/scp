//! UCAN (User Controlled Authorization Networks) token types and capability
//! enforcement for SCP.
//!
//! This module implements the UCAN token data structures and capability URI
//! parsing specified by ADR-016 in `.docs/adrs/phase-3.md`. Every protocol
//! action in an SCP context — message send, outlet invocation, member management,
//! role change — requires a valid UCAN token with matching capabilities.
//!
//! # Types
//!
//! - [`UcanToken`] — Complete UCAN token: header, payload, signature, encoded form.
//! - [`UcanHeader`] — JWT header with algorithm, type, and UCAN version.
//! - [`UcanPayload`] — Token claims: issuer, audience, capabilities, nonce, proofs.
//! - [`Attenuation`] — A single capability grant: resource URI + action.
//! - [`UcanError`] — Error type for UCAN operations.
//!
//! # Capability URIs
//!
//! Resource URIs follow the format `scp:ctx:{context_id}/{capability}`.
//! Wildcards are supported: `scp:ctx:*/messages:write` matches any context.
//! See the [`capability`] module for parsing and matching.
//!
//! # Examples
//!
//! ```
//! use scp_protocol::crypto::ucan::{UcanToken, UcanHeader, UcanPayload, Attenuation};
//!
//! let header = UcanHeader::new();
//! assert_eq!(header.alg, "EdDSA");
//! assert_eq!(header.typ, "JWT");
//! assert_eq!(header.ucv, "0.10.0");
//!
//! let attenuation = Attenuation {
//!     with: "scp:ctx:abc123/messages:write".to_owned(),
//!     can: "write".to_owned(),
//! };
//! assert_eq!(attenuation.with, "scp:ctx:abc123/messages:write");
//! ```
//!
//! See ADR-016 in `.docs/adrs/phase-3.md` for the full specification.

pub mod capability;
pub mod nonce;
pub mod revoke;
pub mod spending;
pub mod validate;

use serde::{Deserialize, Serialize};

pub use capability::CapabilityUri;
pub use spending::{
    Amount, BudgetTracker, CurrencyCode, DEFAULT_SPENDING_KEY_SCOPE, MintSpendingParams,
    SpendingCapability, SpendingError, SpendingScope,
};

// ---------------------------------------------------------------------------
// UcanError
// ---------------------------------------------------------------------------

/// Errors produced by UCAN operations.
///
/// Each variant covers a distinct failure mode in UCAN token handling.
/// See ADR-016 for the full validation pipeline specification.
#[derive(Debug, thiserror::Error)]
pub enum UcanError {
    /// The token string is malformed (wrong number of JWT segments, invalid
    /// base64url encoding, etc.).
    #[error("malformed token: {0}")]
    MalformedToken(String),

    /// JSON deserialization of the header or payload failed.
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),

    /// The header `alg` field is not `"EdDSA"`.
    #[error("unsupported algorithm: expected EdDSA, got {0}")]
    UnsupportedAlgorithm(String),

    /// The header `ucv` field does not match the expected UCAN version.
    #[error("unsupported UCAN version: expected 0.10.0, got {0}")]
    UnsupportedVersion(String),

    /// Ed25519 signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// The root issuer DID does not match the context creator DID.
    #[error("invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer {
        /// The expected context creator DID.
        expected: String,
        /// The actual issuer DID found in the root token.
        actual: String,
    },

    /// The token's audience DID does not match the presenting agent's DID.
    #[error("audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch {
        /// The expected presenting agent DID.
        expected: String,
        /// The actual audience DID in the token.
        actual: String,
    },

    /// The token expiry exceeds the maximum allowed (now + 24 hours).
    #[error("expiry too far in the future: {0}s exceeds 24h maximum")]
    ExpiryTooFar(u64),

    /// The token has expired (`exp <= now`).
    #[error("token expired")]
    TokenExpired,

    /// The token is not yet valid (`nbf > now`).
    #[error("token not yet valid")]
    TokenNotYetValid,

    /// The token's time range is invalid (`nbf >= exp`).
    #[error("invalid time range: nbf ({nbf}) must be less than exp ({exp})")]
    InvalidTimeRange {
        /// The `nbf` (not-before) timestamp.
        nbf: u64,
        /// The `exp` (expiry) timestamp.
        exp: u64,
    },

    /// The nonce has been seen before in this context.
    #[error("nonce reused: {0}")]
    NonceReused(String),

    /// The nonce timestamp is too far in the past.
    #[error("nonce too old: {0}")]
    NonceTooOld(String),

    /// The nonce timestamp is too far in the future.
    #[error("nonce from the future: {0}")]
    NonceFuture(String),

    /// The nonce format is invalid.
    #[error("invalid nonce format: {0}")]
    NonceFormatInvalid(String),

    /// The nonce tracker has reached its capacity limit and all entries are
    /// still within their retention window.
    #[error("nonce tracker full: capacity {0} reached with no expired entries to prune")]
    NonceTrackerFull(usize),

    /// The requested capability is not within the context's ceiling.
    #[error("capability outside ceiling: {0}")]
    CapabilityOutsideCeiling(String),

    /// The requested capability is not granted by the token's attestations.
    #[error("capability not granted: {0}")]
    CapabilityNotGranted(String),

    /// A delegation in the proof chain widens capabilities (violates attenuation).
    #[error("attenuation violation: {0}")]
    AttenuationViolation(String),

    /// The delegation chain is broken (parent `aud` does not match child `iss`).
    #[error("delegation chain broken: {0}")]
    DelegationChainBroken(String),

    /// A circular delegation was detected in the proof chain (e.g., A->B->A).
    #[error("circular delegation detected: {0}")]
    CircularDelegation(String),

    /// The token has been revoked.
    #[error("token revoked: {0}")]
    TokenRevoked(String),

    /// The key used to sign the token does not match the `scp_key_scope`
    /// declared in the token's facts. For example, a token scoped to
    /// `#agent` was signed by the `#active` key.
    ///
    /// See ADR-039 acceptance criterion 7 and SCP-AB-013.
    #[error("key scope mismatch: token scoped to {expected_scope} but signed by {actual_kid}")]
    KeyScopeMismatch {
        /// The scope declared in `fct.scp_key_scope` (e.g., `"#agent"`).
        expected_scope: String,
        /// The `kid` header value or default key ID (e.g., `"#active"`).
        actual_kid: String,
    },

    /// Self-delegation (`iss == aud`) is not permitted without a key scope.
    ///
    /// Self-delegation is only valid when `fct.scp_key_scope` is present,
    /// indicating key-specific delegation within a shared DID (ADR-039).
    /// Without key scope, `iss == aud` is a safety violation — a DID should
    /// not delegate to itself without purpose.
    ///
    /// See ADR-039 and SCP-AB-013.
    #[error("self-delegation (iss == aud) requires scp_key_scope in facts")]
    SelfDelegationWithoutKeyScope,

    /// An agent key (`#agent`) attempted a Category A action (DID document
    /// modification, pre-rotation, identity migration). The action was rejected
    /// and a custody violation attestation should be generated.
    ///
    /// Category A actions are protocol-immutable: only `#0` or `#active` may
    /// sign them. This is Enforcement Stack layer 3 (ADR-039): all conformant
    /// verifiers reject these actions and log a custody violation.
    ///
    /// See ADR-039 and SCP-AB-020.
    #[error("Category A violation: {action} signed by agent key (kid={kid})")]
    CategoryAViolation {
        /// The action that was attempted (e.g., `"did_document:update"`).
        action: String,
        /// The key identifier that signed the token (e.g., `"#agent"`).
        kid: String,
    },

    /// The token grants a capability ADR-039 reserves to the Identity Key
    /// (`#0`), and no key that can sign a UCAN can carry that authority.
    ///
    /// [`scp_did::SigningKeyId`] admits `#active` and `#agent` and nothing
    /// else, so `#0` never signs a UCAN. Authority for a DID-document write
    /// comes from the `#0` signature on the published document, never from a
    /// capability token, which makes such a grant malformed rather than a
    /// custody violation. A verifier reports it as an error and records
    /// nothing against the signer's reputation. When `#agent` signed the
    /// token, [`UcanError::CategoryAViolation`] fires first, because the
    /// agent key crossing the boundary is the more specific finding.
    ///
    /// See spec §4.9.1 rule 2 and
    /// [`crate::trust::custody_violation::requires_identity_key`].
    #[error(
        "capability reserved to the identity key: {action} cannot be granted by a UCAN (kid={kid})"
    )]
    IdentityKeyReservedCapability {
        /// The capability the token granted (e.g., `"did_document:update"`).
        action: String,
        /// The key identifier that signed the token (e.g., `"#active"`).
        kid: String,
    },

    /// The revoker is not authorized to revoke the token (must be the token's
    /// issuer or the context creator).
    #[error("revocation unauthorized: {0}")]
    RevocationUnauthorized(String),

    /// A revocation operation failed (MLS distribution or event log append).
    #[error("revocation failed: {0}")]
    RevocationFailed(String),

    /// Capability URI parsing failed.
    #[error("invalid capability URI: {0}")]
    InvalidCapabilityUri(String),

    /// A child delegation's invocation caveats failed the per-field
    /// [`InvocationCaveats::narrow`](crate::trust::caveats::InvocationCaveats::narrow)
    /// check at Step 7b (attenuation). Carries the structured
    /// [`AttenuationViolation`](crate::trust::caveats::AttenuationViolation)
    /// so SDK consumers can match on the exact rule that fired.
    ///
    /// Maps to error code [`crate::CODE_AUTHORIZATION_ATTENUATION`]
    /// (`SCP-OUTLET-6114`) with the per-violation slug from
    /// [`crate::trust::caveats::AttenuationViolation::slug`].
    #[error("caveat attenuation violation: {0}")]
    CaveatAttenuationViolation(crate::trust::caveats::AttenuationViolation),

    /// The presenting token's invocation caveats failed the Step 11b time-box
    /// check (`valid_from` / `valid_until` / `hours_of_day` / `days_of_week`).
    ///
    /// Maps to error code [`crate::CODE_AUTHORIZATION_DENIED`]
    /// (`SCP-OUTLET-6110`) with slug `authorization.time-box-violation`.
    #[error("caveat time-box violation: {0}")]
    CaveatTimeBoxViolation(String),
}

// ---------------------------------------------------------------------------
// UcanHeader
// ---------------------------------------------------------------------------

/// JWT header for a UCAN token.
///
/// SCP UCAN tokens use `EdDSA` (Ed25519) signatures and conform to UCAN
/// specification version 0.10.0. The header is serialized as the first
/// segment of the JWT.
///
/// The optional `kid` field (Key ID, per RFC 7515) identifies which
/// verification method on the issuer's DID document signed this token.
/// When present, verifiers resolve the public key from the specified
/// verification method (e.g., `"#active"` or `"#agent"`). When absent,
/// verifiers default to `#active`. See ADR-039 acceptance criterion 6.
///
/// See ADR-016 acceptance criterion 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcanHeader {
    /// Signing algorithm. Always `"EdDSA"` for SCP.
    pub alg: String,
    /// Token type. Always `"JWT"` (UCAN is JWT-based).
    pub typ: String,
    /// UCAN specification version. Always `"0.10.0"`.
    pub ucv: String,
    /// Optional Key ID per RFC 7515 (ADR-039). Identifies which verification
    /// method on the issuer's DID document signed this token. Values are
    /// verification method fragment identifiers: `"#active"` for the human
    /// signing key, `"#agent"` for the agent signing key. When absent,
    /// verifiers default to `#active`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl UcanHeader {
    /// Creates a new UCAN header with the SCP-mandated defaults.
    ///
    /// - `alg`: `"EdDSA"`
    /// - `typ`: `"JWT"`
    /// - `ucv`: `"0.10.0"`
    #[must_use]
    pub fn new() -> Self {
        Self {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: None,
        }
    }

    /// Creates a new UCAN header with a Key ID (ADR-039).
    ///
    /// The `kid` identifies which verification method on the issuer's DID
    /// document signed this token (e.g., `"#active"` or `"#agent"`).
    #[must_use]
    pub fn with_kid(kid: impl Into<String>) -> Self {
        Self {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: Some(kid.into()),
        }
    }

    /// Returns the `SigningKeyId` corresponding to this header's `kid` field.
    ///
    /// Returns `SigningKeyId::Active` when `kid` is `None` or `"#active"`,
    /// `SigningKeyId::Agent` when `kid` is `"#agent"`.
    ///
    /// Unknown `kid` values default to `SigningKeyId::Active` for backward
    /// compatibility (fail-open on identification, fail-closed on enforcement).
    #[must_use]
    pub fn signing_key_id(&self) -> scp_did::SigningKeyId {
        match self.kid.as_deref() {
            Some("#agent") => scp_did::SigningKeyId::Agent,
            _ => scp_did::SigningKeyId::Active,
        }
    }

    /// Validates that the header fields match the expected SCP UCAN values.
    ///
    /// Returns `Ok(())` if valid, or a specific [`UcanError`] variant describing
    /// the mismatch.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::UnsupportedAlgorithm`] if `alg` is not `"EdDSA"`.
    /// Returns [`UcanError::UnsupportedVersion`] if `ucv` is not `"0.10.0"`.
    pub fn validate(&self) -> Result<(), UcanError> {
        if self.alg != "EdDSA" {
            return Err(UcanError::UnsupportedAlgorithm(self.alg.clone()));
        }
        if self.ucv != "0.10.0" {
            return Err(UcanError::UnsupportedVersion(self.ucv.clone()));
        }
        Ok(())
    }
}

impl Default for UcanHeader {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Attenuation
// ---------------------------------------------------------------------------

/// A single capability grant within a UCAN token.
///
/// Each attenuation specifies a resource URI and an action. The resource URI
/// follows the SCP capability URI format: `scp:ctx:{context_id}/{resource}:{action}`,
/// where compound resources use underscores (e.g. `outlet_invoke`, `context_child`).
///
/// The `can` field holds the action portion (e.g. `"*"`, `"calculator"`,
/// `"write"`, `"propose"`). See [`CapabilityUri`]
/// for the full URI format and [`Capability::ucan_resource_action`](crate::context::roles::Capability::ucan_resource_action)
/// for the mapping from canonical colon-format to UCAN format.
///
/// See ADR-016 acceptance criterion 4 and #1293.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attenuation {
    /// Resource URI: `scp:ctx:{context_id}/{resource}:{action}`.
    ///
    /// Examples:
    /// - `"scp:ctx:abc123/messages:write"`
    /// - `"scp:ctx:abc123/outlet_call:*"`
    /// - `"scp:ctx:*/messages:write"` (wildcard — all contexts)
    pub with: String,
    /// Action on the resource (e.g. `"*"`, `"write"`, `"calculator"`,
    /// `"propose"`). This is the action portion extracted from the `with` URI.
    pub can: String,
}

// ---------------------------------------------------------------------------
// UcanPayload
// ---------------------------------------------------------------------------

/// Claims payload for a UCAN token.
///
/// Contains the issuer and audience DIDs, expiry, optional not-before time,
/// mandatory nonce (spec section 9.5), capability attestations, proof chain
/// CIDs, and optional facts.
///
/// See ADR-016 acceptance criterion 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcanPayload {
    /// Issuer DID — the entity that created and signed this token.
    pub iss: String,
    /// Audience DID — the entity this token is delegated to.
    pub aud: String,
    /// Expiration time as a Unix timestamp (seconds since epoch).
    pub exp: u64,
    /// Optional not-before time as a Unix timestamp. If present, the token
    /// is not valid before this time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// Mandatory nonce for replay prevention (spec section 9.5).
    ///
    /// Format: `{unix_millis_timestamp}-{16_random_bytes_hex}`.
    pub nnc: String,
    /// Capabilities granted by this token.
    pub att: Vec<Attenuation>,
    /// Proof chain — CIDs of parent UCAN tokens forming the delegation chain.
    /// Empty for root tokens issued by the context creator.
    pub prf: Vec<String>,
    /// Optional facts — arbitrary JSON data attached to the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fct: Option<serde_json::Value>,
    /// §7.3.8 invocation caveats carried in the UCAN `nb` field. Absent when
    /// the token carries no caveat-level constraints — preserves backward
    /// compatibility with tokens that have no `nb` field at all.
    ///
    /// The wire encoding uses the spec §7.3.8 vocabulary verbatim
    /// (`amountMaxPerCall`, `validFrom`, …) — see
    /// [`crate::trust::caveats::InvocationCaveats`] for the field-level
    /// serialization contract.
    #[serde(rename = "nb", skip_serializing_if = "Option::is_none", default)]
    pub nb: Option<crate::trust::caveats::InvocationCaveats>,
}

// ---------------------------------------------------------------------------
// UcanToken
// ---------------------------------------------------------------------------

/// A complete UCAN token with header, payload, signature, and encoded form.
///
/// The `encoded` field stores the original JWT-format string
/// (`base64url(header).base64url(payload).base64url(signature)`) used for
/// signature verification. The `signature` field stores the raw Ed25519
/// signature bytes.
///
/// See ADR-016 acceptance criterion 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcanToken {
    /// JWT header: algorithm, type, UCAN version.
    pub header: UcanHeader,
    /// Token claims: issuer, audience, capabilities, nonce, proofs.
    pub payload: UcanPayload,
    /// Ed25519 signature over `base64url(header).base64url(payload)`.
    pub signature: Vec<u8>,
    /// Original encoded JWT string for signature verification.
    pub encoded: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // UcanHeader
    // -----------------------------------------------------------------------

    #[test]
    fn ucan_header_new_has_expected_defaults() {
        let header = UcanHeader::new();
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.typ, "JWT");
        assert_eq!(header.ucv, "0.10.0");
        assert!(header.kid.is_none(), "kid must be None by default");
    }

    #[test]
    fn ucan_header_default_matches_new() {
        assert_eq!(UcanHeader::default(), UcanHeader::new());
    }

    #[test]
    fn ucan_header_validate_accepts_valid_header() {
        let header = UcanHeader::new();
        assert!(header.validate().is_ok());
    }

    #[test]
    fn ucan_header_validate_rejects_wrong_algorithm() {
        let header = UcanHeader {
            alg: "RS256".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: None,
        };
        let err = header.validate().unwrap_err();
        assert!(matches!(err, UcanError::UnsupportedAlgorithm(ref a) if a == "RS256"));
    }

    #[test]
    fn ucan_header_validate_rejects_wrong_version() {
        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.9.0".to_owned(),
            kid: None,
        };
        let err = header.validate().unwrap_err();
        assert!(matches!(err, UcanError::UnsupportedVersion(ref v) if v == "0.9.0"));
    }

    #[test]
    fn ucan_header_serialization_roundtrip() {
        let header = UcanHeader::new();
        let json = serde_json::to_string(&header).unwrap();
        let deserialized: UcanHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(header, deserialized);
    }

    #[test]
    fn ucan_header_with_kid_sets_kid() {
        let header = UcanHeader::with_kid("#agent".to_owned());
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.typ, "JWT");
        assert_eq!(header.ucv, "0.10.0");
        assert_eq!(header.kid, Some("#agent".to_owned()));
    }

    #[test]
    fn ucan_header_with_kid_validates_successfully() {
        let header = UcanHeader::with_kid("#active".to_owned());
        assert!(header.validate().is_ok());
    }

    #[test]
    fn ucan_header_kid_omitted_from_json_when_none() {
        let header = UcanHeader::new();
        let json = serde_json::to_string(&header).unwrap();
        assert!(
            !json.contains("kid"),
            "kid must not appear in JSON when None"
        );
    }

    #[test]
    fn ucan_header_kid_included_in_json_when_present() {
        let header = UcanHeader::with_kid("#agent".to_owned());
        let json = serde_json::to_string(&header).unwrap();
        assert!(
            json.contains(r##""kid":"#agent""##),
            "kid must appear in JSON: {json}"
        );
    }

    #[test]
    fn ucan_header_with_kid_serialization_roundtrip() {
        let header = UcanHeader::with_kid("#agent".to_owned());
        let json = serde_json::to_string(&header).unwrap();
        let deserialized: UcanHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(header, deserialized);
    }

    #[test]
    fn ucan_header_deserializes_without_kid_field() {
        // Backward compatibility: JSON without kid field deserializes to kid: None.
        let json = r#"{"alg":"EdDSA","typ":"JWT","ucv":"0.10.0"}"#;
        let header: UcanHeader = serde_json::from_str(json).unwrap();
        assert!(header.kid.is_none());
    }

    // -----------------------------------------------------------------------
    // Attenuation
    // -----------------------------------------------------------------------

    #[test]
    fn attenuation_serialization_roundtrip() {
        let att = Attenuation {
            with: "scp:ctx:abc123/messages:write".to_owned(),
            can: "write".to_owned(),
        };
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: Attenuation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, deserialized);
    }

    #[test]
    fn attenuation_clone_eq() {
        let att = Attenuation {
            with: "scp:ctx:abc123/outlet_call:assistant".to_owned(),
            can: "invoke".to_owned(),
        };
        let cloned = att.clone();
        assert_eq!(att, cloned);
    }

    // -----------------------------------------------------------------------
    // UcanPayload
    // -----------------------------------------------------------------------

    #[test]
    fn ucan_payload_serialization_roundtrip() {
        let payload = UcanPayload {
            iss: "did:dht:z6MkCreator".to_owned(),
            aud: "did:dht:z6MkMember".to_owned(),
            exp: 1_700_000_000,
            nbf: Some(1_699_999_000),
            nnc: "1699999000000-aabbccdd11223344".to_owned(),
            att: vec![Attenuation {
                with: "scp:ctx:abc123/messages:write".to_owned(),
                can: "write".to_owned(),
            }],
            prf: vec!["bafyreiabc123".to_owned()],
            fct: Some(serde_json::json!({"note": "test token"})),
            nb: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: UcanPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn ucan_payload_optional_fields_omitted_when_none() {
        let payload = UcanPayload {
            iss: "did:dht:z6MkCreator".to_owned(),
            aud: "did:dht:z6MkMember".to_owned(),
            exp: 1_700_000_000,
            nbf: None,
            nnc: "1699999000000-aabbccdd11223344".to_owned(),
            att: vec![],
            prf: vec![],
            fct: None,
            nb: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        // nbf and fct should not appear in the JSON when None
        assert!(!json.contains("nbf"));
        assert!(!json.contains("fct"));
    }

    #[test]
    fn ucan_payload_deserializes_without_optional_fields() {
        let json = r#"{
            "iss": "did:dht:z6MkCreator",
            "aud": "did:dht:z6MkMember",
            "exp": 1700000000,
            "nnc": "1699999000000-aabbccdd11223344",
            "att": [],
            "prf": []
        }"#;
        let payload: UcanPayload = serde_json::from_str(json).unwrap();
        assert!(payload.nbf.is_none());
        assert!(payload.fct.is_none());
    }

    // -----------------------------------------------------------------------
    // UcanToken
    // -----------------------------------------------------------------------

    #[test]
    fn ucan_token_construction_and_field_access() {
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: 1_700_000_000,
                nbf: None,
                nnc: "1699999000000-aabbccdd11223344".to_owned(),
                att: vec![Attenuation {
                    with: "scp:ctx:abc123/messages:write".to_owned(),
                    can: "write".to_owned(),
                }],
                prf: vec![],
                fct: None,
                nb: None,
            },
            signature: vec![0u8; 64],
            encoded: "eyJ0eXAi...".to_owned(),
        };

        assert_eq!(token.header.alg, "EdDSA");
        assert_eq!(token.payload.iss, "did:dht:z6MkCreator");
        assert_eq!(token.payload.att.len(), 1);
        assert_eq!(token.signature.len(), 64);
    }

    #[test]
    fn ucan_token_serialization_roundtrip() {
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: 1_700_000_000,
                nbf: None,
                nnc: "1699999000000-aabbccdd11223344".to_owned(),
                att: vec![
                    Attenuation {
                        with: "scp:ctx:abc123/messages:write".to_owned(),
                        can: "write".to_owned(),
                    },
                    Attenuation {
                        with: "scp:ctx:abc123/messages:read".to_owned(),
                        can: "read".to_owned(),
                    },
                ],
                prf: vec!["bafyreiabc123".to_owned()],
                fct: Some(serde_json::json!({"role": "member"})),
                nb: None,
            },
            signature: vec![1u8; 64],
            encoded: "header.payload.signature".to_owned(),
        };
        let json = serde_json::to_string(&token).unwrap();
        let deserialized: UcanToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, deserialized);
    }

    #[test]
    fn ucan_token_clone_eq() {
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: 1_700_000_000,
                nbf: None,
                nnc: "1699999000000-aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
                nb: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };
        let cloned = token.clone();
        assert_eq!(token, cloned);
    }

    // -----------------------------------------------------------------------
    // UcanError display
    // -----------------------------------------------------------------------

    #[test]
    fn ucan_error_display_messages() {
        let err = UcanError::MalformedToken("bad base64".to_owned());
        assert_eq!(err.to_string(), "malformed token: bad base64");

        let err = UcanError::UnsupportedAlgorithm("RS256".to_owned());
        assert_eq!(
            err.to_string(),
            "unsupported algorithm: expected EdDSA, got RS256"
        );

        let err = UcanError::SignatureInvalid;
        assert_eq!(err.to_string(), "signature verification failed");

        let err = UcanError::TokenExpired;
        assert_eq!(err.to_string(), "token expired");

        let err = UcanError::NonceReused("abc-123".to_owned());
        assert_eq!(err.to_string(), "nonce reused: abc-123");

        let err = UcanError::CapabilityOutsideCeiling("messages:admin".to_owned());
        assert_eq!(
            err.to_string(),
            "capability outside ceiling: messages:admin"
        );
    }

    #[test]
    fn ucan_error_display_new_variants() {
        let err = UcanError::InvalidIssuer {
            expected: "did:dht:creator".to_owned(),
            actual: "did:dht:imposter".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "invalid issuer: expected did:dht:creator, got did:dht:imposter"
        );

        let err = UcanError::AudienceMismatch {
            expected: "did:dht:member".to_owned(),
            actual: "did:dht:other".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "audience mismatch: expected did:dht:member, got did:dht:other"
        );

        let err = UcanError::ExpiryTooFar(100_000);
        assert_eq!(
            err.to_string(),
            "expiry too far in the future: 100000s exceeds 24h maximum"
        );

        let err = UcanError::NonceTrackerFull(100_000);
        assert_eq!(
            err.to_string(),
            "nonce tracker full: capacity 100000 reached with no expired entries to prune"
        );
    }

    #[test]
    fn ucan_error_display_key_scope_variants() {
        let err = UcanError::KeyScopeMismatch {
            expected_scope: "#agent".to_owned(),
            actual_kid: "#active".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "key scope mismatch: token scoped to #agent but signed by #active"
        );

        let err = UcanError::SelfDelegationWithoutKeyScope;
        assert_eq!(
            err.to_string(),
            "self-delegation (iss == aud) requires scp_key_scope in facts"
        );
    }
}
