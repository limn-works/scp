//! Identity link attestation types (spec §3.5.1, §3.5.2).
//!
//! Implements the `IdentityLinkAttestation` wire format for cryptographically
//! proving ownership of external platform identities (X/Twitter, GitHub,
//! Discord, etc.). Attestations enable three critical flows:
//!
//! 1. **Social graph import** — resolve platform handles against known
//!    attestations to discover SCP contacts.
//! 2. **Shadow identity claiming** — claim bridge-created shadow identities
//!    by presenting a matching attestation (§3.5.3).
//! 3. **Cross-platform reputation continuity** — trust judgments follow
//!    a person across platforms via cryptographic proof of identity linkage.
//!
//! Each attestation is a self-signed claim that a DID controls a specific
//! external identity, backed by one of four verification methods (§3.5.2):
//! OAuth, signed post, DNS record, or challenge-response.
//!
//! The canonical serialization is `MessagePack` (§17). The signature scope
//! covers all fields except the `signature` field itself, serialized with
//! sorted-key encoding per §17.1.
//!
//! See spec §3.5.1 (wire format), §3.5.2 (verification protocol),
//! §3.5.3 (shadow identity claiming).

use std::borrow::Cow;

use scp_identity::DID;
use serde::{Deserialize, Serialize};

use crate::crypto::ed25519::verify_ed25519_signature;

// ---------------------------------------------------------------------------
// Renewal interval constants (§3.5.2)
// ---------------------------------------------------------------------------

/// OAuth verification renewal interval: 30 days.
///
/// OAuth tokens expire and accounts may be revoked; frequent re-verification
/// ensures the link is still valid.
pub const RENEWAL_INTERVAL_OAUTH_DAYS: u32 = 30;

/// Signed post verification renewal interval: 90 days.
///
/// Posts may be deleted and accounts may be suspended; periodic re-verification
/// ensures the post (and account) still exist.
pub const RENEWAL_INTERVAL_SIGNED_POST_DAYS: u32 = 90;

/// DNS record verification renewal interval: 180 days.
///
/// DNS records are stable and domain ownership changes slowly; less frequent
/// re-verification is appropriate.
pub const RENEWAL_INTERVAL_DNS_RECORD_DAYS: u32 = 180;

/// Challenge-response verification renewal interval: 60 days.
///
/// No persistent proof exists; freshness of the interaction matters more.
pub const RENEWAL_INTERVAL_CHALLENGE_RESPONSE_DAYS: u32 = 60;

/// Milliseconds per day, for converting renewal intervals to timestamps.
pub const MS_PER_DAY: u64 = 86_400_000;

// ---------------------------------------------------------------------------
// VerificationMethod (§3.5.2)
// ---------------------------------------------------------------------------

/// The method used to verify an identity link attestation (§3.5.2).
///
/// Each method has a defined verification protocol and a recommended renewal
/// interval. The method determines what the `proof` field in
/// [`AttestationEvidence`] contains and how verifiers validate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// OAuth 2.0 authorization code flow (§3.5.2).
    ///
    /// Proof contains the OAuth provider's signed ID token (JWT) or a JSON
    /// object `{ "provider", "subject", "issued_at" }` signed by the
    /// attesting SDK. Verifier validates the JWT against the platform's JWKS.
    ///
    /// Supported platforms: Google, Apple, GitHub, Discord.
    /// Renewal: 30 days.
    Oauth,

    /// Signed post on the target platform (§3.5.2).
    ///
    /// The user posts a message containing their DID string and a nonce.
    /// Proof contains `{ "post_url", "nonce", "posted_at" }`. Verifier
    /// fetches the post via the platform's official API and confirms it
    /// contains the DID and nonce authored by the claimed handle.
    ///
    /// Supported platforms: X/Twitter, Mastodon, Bluesky, Reddit.
    /// Renewal: 90 days.
    SignedPost,

    /// DNS TXT record at `_scp-verify.<domain>` (§3.5.2).
    ///
    /// The user adds a TXT record containing their DID string. Proof
    /// contains `{ "domain", "record_name" }`. Verifier performs a DNS TXT
    /// lookup and confirms the DID is present. DNSSEC validation is
    /// RECOMMENDED where supported.
    ///
    /// Supported platforms: any domain the user controls.
    /// Renewal: 180 days.
    DnsRecord,

    /// Challenge-response via a third-party verifier (§3.5.2).
    ///
    /// A verifier sends a challenge through the platform; the user signs
    /// it with their SCP identity key and returns the signature. Proof
    /// contains `{ "challenge", "response_signature", "verifier_did" }`.
    ///
    /// Renewal: 60 days.
    ChallengeResponse,
}

impl VerificationMethod {
    /// Returns the recommended renewal interval in days for this method (§3.5.2).
    #[must_use]
    pub const fn renewal_interval_days(self) -> u32 {
        match self {
            Self::Oauth => RENEWAL_INTERVAL_OAUTH_DAYS,
            Self::SignedPost => RENEWAL_INTERVAL_SIGNED_POST_DAYS,
            Self::DnsRecord => RENEWAL_INTERVAL_DNS_RECORD_DAYS,
            Self::ChallengeResponse => RENEWAL_INTERVAL_CHALLENGE_RESPONSE_DAYS,
        }
    }

    /// Returns the recommended renewal interval in milliseconds for this method.
    #[must_use]
    pub const fn renewal_interval_ms(self) -> u64 {
        self.renewal_interval_days() as u64 * MS_PER_DAY
    }

    /// Returns the wire-format string for this method (matches `evidence.method`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oauth => "oauth",
            Self::SignedPost => "signed_post",
            Self::DnsRecord => "dns_record",
            Self::ChallengeResponse => "challenge_response",
        }
    }
}

// ---------------------------------------------------------------------------
// AttestationClaim (§3.5.1)
// ---------------------------------------------------------------------------

/// The claim portion of an identity link attestation (§3.5.1).
///
/// Records which external platform identity is being claimed by the issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationClaim {
    /// Platform identifier (e.g., "x.com", "github.com", "discord.com").
    pub platform: String,

    /// Handle on the platform (e.g., "@alice", "alice123").
    pub platform_handle: String,

    /// Platform-specific immutable user ID (e.g., Twitter user ID).
    ///
    /// When available, this provides a stable identifier that survives
    /// handle changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_id: Option<String>,

    /// Always `"self_attestation"` for identity link attestations.
    pub link_type: Cow<'static, str>,
}

impl AttestationClaim {
    /// The canonical link type value for identity link attestations.
    pub const SELF_ATTESTATION: &'static str = "self_attestation";

    /// Creates a new claim with the canonical link type.
    #[must_use]
    pub const fn new(
        platform: String,
        platform_handle: String,
        platform_id: Option<String>,
    ) -> Self {
        Self {
            platform,
            platform_handle,
            platform_id,
            link_type: Cow::Borrowed(Self::SELF_ATTESTATION),
        }
    }
}

// ---------------------------------------------------------------------------
// AttestationEvidence (§3.5.1)
// ---------------------------------------------------------------------------

/// Evidence supporting an identity link attestation (§3.5.1).
///
/// Contains the verification method, method-specific proof data, the
/// timestamp of last verification, and an optional third-party verifier DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationEvidence {
    /// Verification method used to establish the link.
    pub method: VerificationMethod,

    /// Method-specific proof data (§3.5.2).
    ///
    /// Contents depend on `method`:
    /// - OAuth: signed ID token (JWT) or signed provider assertion.
    /// - Signed post: `{ "post_url", "nonce", "posted_at" }`.
    /// - DNS record: `{ "domain", "record_name" }`.
    /// - Challenge-response: `{ "challenge", "response_signature", "verifier_did" }`.
    pub proof: String,

    /// Unix timestamp (milliseconds) of last verification.
    pub verified_at: u64,

    /// DID of the third-party verifier, if the evidence was verified by
    /// someone other than the attestation issuer (e.g., challenge-response).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_did: Option<DID>,
}

impl AttestationEvidence {
    /// Returns whether this evidence has expired relative to the given
    /// current timestamp, based on the verification method's renewal interval.
    ///
    /// An evidence record is considered expired when
    /// `now_ms - verified_at > method.renewal_interval_ms()`.
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.verified_at) > self.method.renewal_interval_ms()
    }
}

// ---------------------------------------------------------------------------
// AttestationRevocation (§3.5.1)
// ---------------------------------------------------------------------------

/// Revocation metadata for an identity link attestation (§3.5.1).
///
/// Specifies how verifiers check whether this attestation has been revoked.
/// The canonical method is `"did_document"` — verifiers resolve the issuer's
/// DID document and check the `AttestationRevocations` service endpoint
/// (§18.2.2) for the attestation's ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRevocation {
    /// Revocation check method. Currently always `"did_document"`.
    pub method: Cow<'static, str>,

    /// DID document service endpoint path for revocation status.
    pub endpoint: String,
}

impl AttestationRevocation {
    /// The canonical revocation method value.
    pub const DID_DOCUMENT: &'static str = "did_document";

    /// Creates a new revocation entry with the canonical method.
    #[must_use]
    pub const fn new(endpoint: String) -> Self {
        Self {
            method: Cow::Borrowed(Self::DID_DOCUMENT),
            endpoint,
        }
    }
}

// ---------------------------------------------------------------------------
// IdentityLinkAttestation (§3.5.1)
// ---------------------------------------------------------------------------

/// An identity link attestation proving ownership of an external platform
/// identity (§3.5.1).
///
/// This is the complete wire format for identity attestations. The `id` is
/// deterministically derived as `SHA-256(issuer || platform || platform_handle
/// || issued_at)`, hex-encoded. The `signature` covers the canonical
/// `MessagePack` serialization of all other fields (sorted-key encoding per
/// §17.1), signed by the issuer's `#active` or `#agent` key.
///
/// # Verification
///
/// Verifiers check:
/// 1. `signature` validates against the issuer's signing key.
/// 2. `id` matches `hex(SHA-256(issuer || platform || handle || issued_at))`.
/// 3. `expires_at` (if set) has not passed.
/// 4. The attestation is not on the issuer's revocation list (§18.2.2).
/// 5. `evidence.verified_at` is within the method's renewal interval (§3.5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityLinkAttestation {
    /// Deterministic ID: `hex(SHA-256(issuer || platform || handle || issued_at))`.
    pub id: String,

    /// Attestation type. Always `"identity_link"`.
    #[serde(rename = "type")]
    pub attestation_type: Cow<'static, str>,

    /// The DID claiming the external identity (self-attestation issuer).
    pub issuer: DID,

    /// Same as `issuer` for self-attestations.
    pub subject: DID,

    /// Unix timestamp (milliseconds) when the attestation was created.
    pub issued_at: u64,

    /// Optional expiry timestamp (milliseconds). If absent, valid until revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// The platform identity being claimed.
    pub claim: AttestationClaim,

    /// Evidence supporting the claim.
    pub evidence: AttestationEvidence,

    /// Revocation metadata.
    pub revocation: AttestationRevocation,

    /// Ed25519 signature over the canonical `MessagePack` of all other fields.
    ///
    /// The signature is computed using the issuer's Active Signing Key
    /// (`#active`) or Agent Signing Key (`#agent`).
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// The canonical attestation type string.
pub const ATTESTATION_TYPE_IDENTITY_LINK: &str = "identity_link";

impl IdentityLinkAttestation {
    /// Returns whether this attestation has expired based on `expires_at`.
    ///
    /// Returns `false` if `expires_at` is `None` (no expiry set — valid
    /// until revoked).
    #[must_use]
    pub fn is_time_expired(&self, now_ms: u64) -> bool {
        self.expires_at.is_some_and(|exp| now_ms > exp)
    }

    /// Returns whether the evidence needs renewal based on the verification
    /// method's recommended interval (§3.5.2).
    #[must_use]
    pub const fn needs_renewal(&self, now_ms: u64) -> bool {
        self.evidence.is_expired(now_ms)
    }

    /// Returns the renewal deadline (milliseconds) — the timestamp after
    /// which this attestation's evidence is considered stale.
    #[must_use]
    pub const fn renewal_deadline_ms(&self) -> u64 {
        self.evidence
            .verified_at
            .saturating_add(self.evidence.method.renewal_interval_ms())
    }

    /// Computes the deterministic attestation ID from its components.
    ///
    /// `id = hex(SHA-256("SCP-ATTESTATION-ID-V1:" || len(issuer_did) || issuer_did || len(platform) || platform || len(platform_handle) || platform_handle || issued_at_be))`
    ///
    /// The domain separator `"SCP-ATTESTATION-ID-V1:"` ensures this hash
    /// cannot collide with hashes from other SCP subsystems. Each string
    /// field is length-prefixed with its byte length as a 4-byte big-endian
    /// integer to prevent concatenation ambiguity (e.g., platform `"ab"` +
    /// handle `"cd"` vs platform `"a"` + handle `"bcd"`). The `issued_at`
    /// timestamp is encoded as 8-byte big-endian for deterministic
    /// cross-platform computation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // DID/platform strings are far below u32::MAX bytes.
    pub fn compute_id(
        issuer: &DID,
        platform: &str,
        platform_handle: &str,
        issued_at: u64,
    ) -> String {
        use sha2::{Digest, Sha256};

        let issuer_bytes = (*issuer).as_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-ATTESTATION-ID-V1:");
        hasher.update((issuer_bytes.len() as u32).to_be_bytes());
        hasher.update(issuer_bytes);
        hasher.update((platform.len() as u32).to_be_bytes());
        hasher.update(platform.as_bytes());
        hasher.update((platform_handle.len() as u32).to_be_bytes());
        hasher.update(platform_handle.as_bytes());
        hasher.update(issued_at.to_be_bytes());

        let hash = hasher.finalize();
        hex::encode(hash)
    }

    /// Verifies the Ed25519 signature on this attestation.
    ///
    /// Constructs the canonical signing payload (all fields except `signature`,
    /// using the domain-separated canonical hash construction per §9.5.1), then
    /// verifies the signature against the provided public key bytes.
    ///
    /// The canonical form uses domain separator `"SCP-IDENTITY-LINK-ATTESTATION-V1:"`
    /// with fields in a fixed order: `id`, `attestation_type`, `issuer`, `subject`,
    /// `issued_at`, `expires_at` (or absent sentinel), `claim` (`MessagePack`),
    /// `evidence` (`MessagePack`), `revocation` (`MessagePack`).
    ///
    /// # Arguments
    ///
    /// * `public_key` — 32-byte Ed25519 public key (issuer's `#active` or `#agent` key).
    ///
    /// # Errors
    ///
    /// Returns [`AttestationSignatureError::SerializationFailed`] if sub-structs
    /// cannot be serialized to `MessagePack`, or [`AttestationSignatureError::InvalidSignature`]
    /// if the signature does not verify.
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<(), AttestationSignatureError> {
        let canonical = self.canonical_signing_bytes()?;
        verify_ed25519_signature(public_key, &canonical, &self.signature)
            .map_err(AttestationSignatureError::InvalidSignature)
    }

    /// Computes the canonical signing payload for this attestation.
    ///
    /// The payload includes all fields except `signature`, serialized using the
    /// protocol's canonical hash construction (§9.5.1). Sub-structs (`claim`,
    /// `evidence`, `revocation`) are serialized as `MessagePack` bytes and included
    /// as variable-length fields.
    ///
    /// This method is deterministic: identical attestation data always produces
    /// identical bytes, regardless of serde field ordering.
    fn canonical_signing_bytes(&self) -> Result<Vec<u8>, AttestationSignatureError> {
        use crate::crypto::canonical::{CanonicalField, canonical_hash};

        let claim_bytes = rmp_serde::to_vec_named(&self.claim).map_err(|e| {
            AttestationSignatureError::SerializationFailed(format!(
                "claim serialization failed: {e}"
            ))
        })?;
        let evidence_bytes = rmp_serde::to_vec_named(&self.evidence).map_err(|e| {
            AttestationSignatureError::SerializationFailed(format!(
                "evidence serialization failed: {e}"
            ))
        })?;
        let revocation_bytes = rmp_serde::to_vec_named(&self.revocation).map_err(|e| {
            AttestationSignatureError::SerializationFailed(format!(
                "revocation serialization failed: {e}"
            ))
        })?;

        Ok(canonical_hash(
            "SCP-IDENTITY-LINK-ATTESTATION-V1:",
            &[
                CanonicalField::VarBytes(self.id.as_bytes()),
                CanonicalField::VarBytes(self.attestation_type.as_bytes()),
                CanonicalField::VarBytes((*self.issuer).as_bytes()),
                CanonicalField::VarBytes((*self.subject).as_bytes()),
                CanonicalField::U64(self.issued_at),
                self.expires_at
                    .map_or(CanonicalField::Absent, CanonicalField::U64),
                CanonicalField::VarBytes(&claim_bytes),
                CanonicalField::VarBytes(&evidence_bytes),
                CanonicalField::VarBytes(&revocation_bytes),
            ],
        )
        .to_vec())
    }

    /// Validates the structural integrity of this attestation (does NOT
    /// verify the cryptographic signature).
    ///
    /// Checks:
    /// - `attestation_type` is `"identity_link"`.
    /// - `issuer` equals `subject` (self-attestation).
    /// - `id` matches the computed deterministic ID.
    /// - `claim.link_type` is `"self_attestation"`.
    ///
    /// Returns a list of validation errors. Empty list means structurally valid.
    #[must_use]
    pub fn validate_structure(&self) -> Vec<Cow<'static, str>> {
        let mut errors = Vec::new();

        if self.attestation_type != ATTESTATION_TYPE_IDENTITY_LINK {
            errors.push(Cow::Owned(format!(
                "attestation_type must be \"identity_link\", got {:?}",
                self.attestation_type,
            )));
        }

        if self.issuer != self.subject {
            errors.push(Cow::Borrowed(
                "issuer must equal subject for self-attestation",
            ));
        }

        let expected_id = Self::compute_id(
            &self.issuer,
            &self.claim.platform,
            &self.claim.platform_handle,
            self.issued_at,
        );
        if self.id != expected_id {
            errors.push(Cow::Owned(format!(
                "id mismatch: expected {expected_id}, got {}",
                self.id,
            )));
        }

        if self.claim.link_type != AttestationClaim::SELF_ATTESTATION {
            errors.push(Cow::Owned(format!(
                "link_type must be \"self_attestation\", got {:?}",
                self.claim.link_type,
            )));
        }

        errors
    }
}

// ---------------------------------------------------------------------------
// AttestationSignatureError
// ---------------------------------------------------------------------------

/// Error type for identity link attestation signature verification.
#[derive(Debug, thiserror::Error)]
pub enum AttestationSignatureError {
    /// The canonical signing payload could not be serialized.
    #[error("canonical serialization failed: {0}")]
    SerializationFailed(String),

    /// The Ed25519 signature is invalid (wrong key, tampered data, or
    /// malformed signature/key bytes).
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn did(s: &str) -> DID {
        DID::from(s)
    }

    fn make_attestation() -> IdentityLinkAttestation {
        let issuer = did("did:dht:z6MkAlice");
        let platform = "github.com";
        let handle = "alice";
        let issued_at = 1_700_000_000_000_u64;

        IdentityLinkAttestation {
            id: IdentityLinkAttestation::compute_id(&issuer, platform, handle, issued_at),
            attestation_type: Cow::Borrowed(ATTESTATION_TYPE_IDENTITY_LINK),
            issuer: issuer.clone(),
            subject: issuer,
            issued_at,
            expires_at: None,
            claim: AttestationClaim::new(
                platform.to_owned(),
                handle.to_owned(),
                Some("12345".to_owned()),
            ),
            evidence: AttestationEvidence {
                method: VerificationMethod::Oauth,
                proof: r#"{"provider":"github.com","subject":"12345","issued_at":1700000000}"#
                    .to_owned(),
                verified_at: 1_700_000_000_000,
                verifier_did: None,
            },
            revocation: AttestationRevocation::new("/revocations".to_owned()),
            signature: vec![0xAA; 64],
        }
    }

    // -----------------------------------------------------------------------
    // VerificationMethod
    // -----------------------------------------------------------------------

    #[test]
    fn verification_method_renewal_intervals() {
        assert_eq!(VerificationMethod::Oauth.renewal_interval_days(), 30);
        assert_eq!(VerificationMethod::SignedPost.renewal_interval_days(), 90);
        assert_eq!(VerificationMethod::DnsRecord.renewal_interval_days(), 180);
        assert_eq!(
            VerificationMethod::ChallengeResponse.renewal_interval_days(),
            60
        );
    }

    #[test]
    fn verification_method_renewal_ms() {
        assert_eq!(
            VerificationMethod::Oauth.renewal_interval_ms(),
            30 * MS_PER_DAY
        );
        assert_eq!(
            VerificationMethod::DnsRecord.renewal_interval_ms(),
            180 * MS_PER_DAY
        );
    }

    #[test]
    fn verification_method_as_str() {
        assert_eq!(VerificationMethod::Oauth.as_str(), "oauth");
        assert_eq!(VerificationMethod::SignedPost.as_str(), "signed_post");
        assert_eq!(VerificationMethod::DnsRecord.as_str(), "dns_record");
        assert_eq!(
            VerificationMethod::ChallengeResponse.as_str(),
            "challenge_response"
        );
    }

    #[test]
    fn verification_method_serialization_roundtrip() {
        let methods = [
            VerificationMethod::Oauth,
            VerificationMethod::SignedPost,
            VerificationMethod::DnsRecord,
            VerificationMethod::ChallengeResponse,
        ];
        for method in &methods {
            let json = serde_json::to_string(method).unwrap();
            let deserialized: VerificationMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(method, &deserialized);
        }
    }

    // -----------------------------------------------------------------------
    // AttestationClaim
    // -----------------------------------------------------------------------

    #[test]
    fn attestation_claim_construction() {
        let claim = AttestationClaim::new(
            "x.com".to_owned(),
            "@alice".to_owned(),
            Some("999".to_owned()),
        );
        assert_eq!(claim.platform, "x.com");
        assert_eq!(claim.platform_handle, "@alice");
        assert_eq!(claim.platform_id.as_deref(), Some("999"));
        assert_eq!(claim.link_type, "self_attestation");
    }

    #[test]
    fn attestation_claim_without_platform_id() {
        let claim = AttestationClaim::new("mastodon.social".to_owned(), "@bob".to_owned(), None);
        assert!(claim.platform_id.is_none());
    }

    #[test]
    fn attestation_claim_serialization_roundtrip() {
        let claim = AttestationClaim::new(
            "github.com".to_owned(),
            "alice123".to_owned(),
            Some("42".to_owned()),
        );
        let json = serde_json::to_string(&claim).unwrap();
        let deserialized: AttestationClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim, deserialized);
    }

    // -----------------------------------------------------------------------
    // AttestationEvidence
    // -----------------------------------------------------------------------

    #[test]
    fn attestation_evidence_not_expired() {
        let evidence = AttestationEvidence {
            method: VerificationMethod::Oauth,
            proof: "jwt-token".to_owned(),
            verified_at: 1_700_000_000_000,
            verifier_did: None,
        };
        // 15 days later — within 30-day renewal
        let now = 1_700_000_000_000 + 15 * MS_PER_DAY;
        assert!(!evidence.is_expired(now));
    }

    #[test]
    fn attestation_evidence_expired() {
        let evidence = AttestationEvidence {
            method: VerificationMethod::Oauth,
            proof: "jwt-token".to_owned(),
            verified_at: 1_700_000_000_000,
            verifier_did: None,
        };
        // 31 days later — past 30-day renewal
        let now = 1_700_000_000_000 + 31 * MS_PER_DAY;
        assert!(evidence.is_expired(now));
    }

    #[test]
    fn attestation_evidence_exactly_at_boundary() {
        let evidence = AttestationEvidence {
            method: VerificationMethod::SignedPost,
            proof: "post-data".to_owned(),
            verified_at: 1_700_000_000_000,
            verifier_did: None,
        };
        // Exactly at 90 days — not expired (boundary is >)
        let now = 1_700_000_000_000 + 90 * MS_PER_DAY;
        assert!(!evidence.is_expired(now));
    }

    #[test]
    fn attestation_evidence_serialization_roundtrip() {
        let evidence = AttestationEvidence {
            method: VerificationMethod::ChallengeResponse,
            proof: r#"{"challenge":"abc","response_signature":"def","verifier_did":"did:dht:z6MkVerifier"}"#.to_owned(),
            verified_at: 1_700_000_000_000,
            verifier_did: Some(did("did:dht:z6MkVerifier")),
        };
        let json = serde_json::to_string(&evidence).unwrap();
        let deserialized: AttestationEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, deserialized);
    }

    // -----------------------------------------------------------------------
    // AttestationRevocation
    // -----------------------------------------------------------------------

    #[test]
    fn attestation_revocation_construction() {
        let rev = AttestationRevocation::new("/revocations/v1".to_owned());
        assert_eq!(rev.method, "did_document");
        assert_eq!(rev.endpoint, "/revocations/v1");
    }

    #[test]
    fn attestation_revocation_serialization_roundtrip() {
        let rev = AttestationRevocation::new("/attestation-revocations".to_owned());
        let json = serde_json::to_string(&rev).unwrap();
        let deserialized: AttestationRevocation = serde_json::from_str(&json).unwrap();
        assert_eq!(rev, deserialized);
    }

    // -----------------------------------------------------------------------
    // IdentityLinkAttestation
    // -----------------------------------------------------------------------

    #[test]
    fn attestation_compute_id_deterministic() {
        let issuer = did("did:dht:z6MkAlice");
        let id1 = IdentityLinkAttestation::compute_id(&issuer, "github.com", "alice", 1_000_000);
        let id2 = IdentityLinkAttestation::compute_id(&issuer, "github.com", "alice", 1_000_000);
        assert_eq!(id1, id2);
    }

    #[test]
    fn attestation_compute_id_differs_for_different_inputs() {
        let issuer = did("did:dht:z6MkAlice");
        let id1 = IdentityLinkAttestation::compute_id(&issuer, "github.com", "alice", 1_000_000);
        let id2 = IdentityLinkAttestation::compute_id(&issuer, "x.com", "alice", 1_000_000);
        let id3 = IdentityLinkAttestation::compute_id(&issuer, "github.com", "bob", 1_000_000);
        let id4 = IdentityLinkAttestation::compute_id(&issuer, "github.com", "alice", 2_000_000);
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id1, id4);
    }

    #[test]
    fn attestation_validate_structure_valid() {
        let attestation = make_attestation();
        let errors = attestation.validate_structure();
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn attestation_validate_structure_wrong_type() {
        let mut attestation = make_attestation();
        attestation.attestation_type = Cow::Borrowed("wrong_type");
        let errors = attestation.validate_structure();
        assert!(errors.iter().any(|e| e.contains("attestation_type")));
    }

    #[test]
    fn attestation_validate_structure_issuer_subject_mismatch() {
        let mut attestation = make_attestation();
        attestation.subject = did("did:dht:z6MkDifferent");
        let errors = attestation.validate_structure();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("issuer must equal subject"))
        );
    }

    #[test]
    fn attestation_validate_structure_id_mismatch() {
        let mut attestation = make_attestation();
        attestation.id = "bad-id-value".to_owned();
        let errors = attestation.validate_structure();
        assert!(errors.iter().any(|e| e.contains("id mismatch")));
    }

    #[test]
    fn attestation_validate_structure_wrong_link_type() {
        let mut attestation = make_attestation();
        attestation.claim.link_type = Cow::Borrowed("other_attestation");
        let errors = attestation.validate_structure();
        assert!(errors.iter().any(|e| e.contains("link_type")));
    }

    #[test]
    fn attestation_is_time_expired_no_expiry() {
        let attestation = make_attestation();
        assert!(!attestation.is_time_expired(u64::MAX));
    }

    #[test]
    fn attestation_is_time_expired_before_expiry() {
        let mut attestation = make_attestation();
        attestation.expires_at = Some(2_000_000_000_000);
        assert!(!attestation.is_time_expired(1_999_999_999_999));
    }

    #[test]
    fn attestation_is_time_expired_after_expiry() {
        let mut attestation = make_attestation();
        attestation.expires_at = Some(2_000_000_000_000);
        assert!(attestation.is_time_expired(2_000_000_000_001));
    }

    #[test]
    fn attestation_needs_renewal_fresh() {
        let attestation = make_attestation();
        // 5 days later — well within 30-day OAuth renewal
        let now = attestation.evidence.verified_at + 5 * MS_PER_DAY;
        assert!(!attestation.needs_renewal(now));
    }

    #[test]
    fn attestation_needs_renewal_stale() {
        let attestation = make_attestation();
        // 31 days later — past 30-day OAuth renewal
        let now = attestation.evidence.verified_at + 31 * MS_PER_DAY;
        assert!(attestation.needs_renewal(now));
    }

    #[test]
    fn attestation_renewal_deadline_ms() {
        let attestation = make_attestation();
        let expected = attestation.evidence.verified_at + 30 * MS_PER_DAY;
        assert_eq!(attestation.renewal_deadline_ms(), expected);
    }

    #[test]
    fn attestation_serialization_roundtrip_json() {
        let attestation = make_attestation();
        let json = serde_json::to_string(&attestation).unwrap();
        let deserialized: IdentityLinkAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn attestation_serialization_roundtrip_msgpack() {
        let attestation = make_attestation();
        let bytes = rmp_serde::to_vec_named(&attestation).unwrap();
        let deserialized: IdentityLinkAttestation = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn attestation_with_expiry_serialization() {
        let mut attestation = make_attestation();
        attestation.expires_at = Some(1_800_000_000_000);
        let json = serde_json::to_string(&attestation).unwrap();
        assert!(json.contains("1800000000000"));
        let deserialized: IdentityLinkAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expires_at, Some(1_800_000_000_000));
    }

    #[test]
    fn attestation_dns_record_method_renewal() {
        let mut attestation = make_attestation();
        attestation.evidence.method = VerificationMethod::DnsRecord;
        // 100 days — within 180-day DNS renewal
        let now = attestation.evidence.verified_at + 100 * MS_PER_DAY;
        assert!(!attestation.needs_renewal(now));
        // 181 days — past renewal
        let now = attestation.evidence.verified_at + 181 * MS_PER_DAY;
        assert!(attestation.needs_renewal(now));
    }

    // -----------------------------------------------------------------------
    // deny_unknown_fields
    // -----------------------------------------------------------------------

    #[test]
    fn attestation_rejects_unknown_fields_json() {
        let attestation = make_attestation();
        let mut json: serde_json::Value = serde_json::to_value(&attestation).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("unknown_field".to_owned(), serde_json::Value::Bool(true));
        let result = serde_json::from_value::<IdentityLinkAttestation>(json);
        assert!(result.is_err(), "should reject unknown fields");
    }

    // -----------------------------------------------------------------------
    // Signature verification
    // -----------------------------------------------------------------------

    /// Creates a properly signed attestation using the given signing key.
    fn make_signed_attestation(signing_key: &ed25519_dalek::SigningKey) -> IdentityLinkAttestation {
        use ed25519_dalek::Signer;

        let verifying_key = signing_key.verifying_key();
        // Encode DID from verifying key bytes
        let did_str = format!("did:dht:z6Mk{}", hex::encode(verifying_key.as_bytes()));
        let issuer = did(&did_str);
        let platform = "github.com";
        let handle = "alice";
        let issued_at = 1_700_000_000_000_u64;

        let mut attestation = IdentityLinkAttestation {
            id: IdentityLinkAttestation::compute_id(&issuer, platform, handle, issued_at),
            attestation_type: Cow::Borrowed(ATTESTATION_TYPE_IDENTITY_LINK),
            issuer: issuer.clone(),
            subject: issuer,
            issued_at,
            expires_at: None,
            claim: AttestationClaim::new(
                platform.to_owned(),
                handle.to_owned(),
                Some("12345".to_owned()),
            ),
            evidence: AttestationEvidence {
                method: VerificationMethod::Oauth,
                proof: r#"{"provider":"github.com","subject":"12345","issued_at":1700000000}"#
                    .to_owned(),
                verified_at: 1_700_000_000_000,
                verifier_did: None,
            },
            revocation: AttestationRevocation::new("/revocations".to_owned()),
            signature: Vec::new(), // placeholder — will be replaced
        };

        // Sign the canonical bytes
        let canonical = attestation.canonical_signing_bytes().unwrap();
        let sig = signing_key.sign(&canonical);
        attestation.signature = sig.to_bytes().to_vec();

        attestation
    }

    fn test_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        ed25519_dalek::SigningKey::from_bytes(&secret)
    }

    #[test]
    fn verify_signature_valid() {
        let sk = test_signing_key(0xAA);
        let attestation = make_signed_attestation(&sk);
        let vk = sk.verifying_key();
        let result = attestation.verify_signature(vk.as_bytes());
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn verify_signature_wrong_key() {
        let sk = test_signing_key(0xAA);
        let wrong_key = test_signing_key(0xBB);
        let attestation = make_signed_attestation(&sk);
        let wrong_verifying_key = wrong_key.verifying_key();
        let result = attestation.verify_signature(wrong_verifying_key.as_bytes());
        assert!(result.is_err(), "should fail with wrong key");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("signature verification failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_signature_tampered_id() {
        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        attestation.id = "tampered-id".to_owned();
        let vk = sk.verifying_key();
        let result = attestation.verify_signature(vk.as_bytes());
        assert!(result.is_err(), "should fail with tampered id");
    }

    #[test]
    fn verify_signature_tampered_claim() {
        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        attestation.claim.platform_handle = "mallory".to_owned();
        let vk = sk.verifying_key();
        let result = attestation.verify_signature(vk.as_bytes());
        assert!(result.is_err(), "should fail with tampered claim");
    }

    #[test]
    fn verify_signature_tampered_issuer() {
        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        attestation.issuer = did("did:dht:z6MkTampered");
        let vk = sk.verifying_key();
        let result = attestation.verify_signature(vk.as_bytes());
        assert!(result.is_err(), "should fail with tampered issuer");
    }

    #[test]
    fn verify_signature_tampered_evidence() {
        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        attestation.evidence.verified_at = 999_999_999_999;
        let vk = sk.verifying_key();
        let result = attestation.verify_signature(vk.as_bytes());
        assert!(result.is_err(), "should fail with tampered evidence");
    }

    #[test]
    fn verify_signature_tampered_revocation() {
        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        attestation.revocation.endpoint = "/evil".to_owned();
        let vk = sk.verifying_key();
        let result = attestation.verify_signature(vk.as_bytes());
        assert!(result.is_err(), "should fail with tampered revocation");
    }

    #[test]
    fn verify_signature_tampered_expires_at() {
        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        // Original has expires_at = None; set it to Some to tamper
        attestation.expires_at = Some(9_999_999_999_999);
        let vk = sk.verifying_key();
        let result = attestation.verify_signature(vk.as_bytes());
        assert!(result.is_err(), "should fail with tampered expires_at");
    }

    #[test]
    fn verify_signature_invalid_signature_bytes() {
        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        // Corrupt the signature
        attestation.signature[0] ^= 0xFF;
        let vk = sk.verifying_key();
        let result = attestation.verify_signature(vk.as_bytes());
        assert!(result.is_err(), "should fail with corrupted signature");
    }

    #[test]
    fn verify_signature_short_public_key() {
        let sk = test_signing_key(0xAA);
        let attestation = make_signed_attestation(&sk);
        let result = attestation.verify_signature(&[0u8; 16]);
        assert!(result.is_err(), "should fail with short public key");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_signature_short_signature() {
        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        attestation.signature = vec![0u8; 32]; // too short
        let vk = sk.verifying_key();
        let result = attestation.verify_signature(vk.as_bytes());
        assert!(result.is_err(), "should fail with short signature");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("64 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_signature_with_expires_at_set() {
        use ed25519_dalek::Signer;

        let sk = test_signing_key(0xCC);
        let vk = sk.verifying_key();
        let did_str = format!("did:dht:z6Mk{}", hex::encode(vk.as_bytes()));
        let issuer = did(&did_str);
        let platform = "x.com";
        let handle = "@alice";
        let issued_at = 1_700_000_000_000_u64;

        let mut attestation = IdentityLinkAttestation {
            id: IdentityLinkAttestation::compute_id(&issuer, platform, handle, issued_at),
            attestation_type: Cow::Borrowed(ATTESTATION_TYPE_IDENTITY_LINK),
            issuer: issuer.clone(),
            subject: issuer,
            issued_at,
            expires_at: Some(1_800_000_000_000),
            claim: AttestationClaim::new(platform.to_owned(), handle.to_owned(), None),
            evidence: AttestationEvidence {
                method: VerificationMethod::SignedPost,
                proof:
                    r#"{"post_url":"https://x.com/alice/123","nonce":"abc","posted_at":1700000000}"#
                        .to_owned(),
                verified_at: 1_700_000_000_000,
                verifier_did: None,
            },
            revocation: AttestationRevocation::new("/revocations".to_owned()),
            signature: Vec::new(),
        };

        let canonical = attestation.canonical_signing_bytes().unwrap();
        attestation.signature = sk.sign(&canonical).to_bytes().to_vec();

        let result = attestation.verify_signature(vk.as_bytes());
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn canonical_signing_bytes_deterministic() {
        let sk = test_signing_key(0xDD);
        let attestation = make_signed_attestation(&sk);
        let bytes1 = attestation.canonical_signing_bytes().unwrap();
        let bytes2 = attestation.canonical_signing_bytes().unwrap();
        assert_eq!(bytes1, bytes2, "canonical bytes must be deterministic");
    }
}
