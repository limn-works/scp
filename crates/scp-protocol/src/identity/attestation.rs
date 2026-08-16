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

use scp_did::DID;
use serde::{Deserialize, Serialize};

use scp_crypto::verify_ed25519_signature;

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

/// Seconds per day, for converting renewal intervals to timestamps.
///
/// All attestation timestamps use seconds (spec §3.5.1). Wire format,
/// `verified_at`, `issued_at`, and expiry are all Unix seconds.
pub const SECS_PER_DAY: u64 = 86_400;

// ---------------------------------------------------------------------------
// AttestationClass (§3.5.2)
// ---------------------------------------------------------------------------

/// Classification of verification methods by their proof model (§3.5.2).
///
/// Determines cache TTLs and verification strategy:
/// - **Cryptographic** — backed by cryptographic verification (OAuth JWTs
///   verified against JWKS, challenge-response signatures). Can be verified
///   without re-fetching external resources. Cache TTL: 24h.
/// - **Reference** — requires fetching an external resource to verify (signed
///   posts, DNS records). Verification requires network access. Cache TTL: 1h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationClass {
    /// Self-verifying via cryptographic proof (OAuth, challenge-response).
    Cryptographic,
    /// Requires fetching external resource to verify (signed post, DNS record).
    Reference,
}

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

impl std::str::FromStr for VerificationMethod {
    type Err = String;

    /// Parses a wire-format string into a `VerificationMethod`.
    ///
    /// Accepted values: `"oauth"`, `"signed_post"`, `"dns_record"`,
    /// `"challenge_response"`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "oauth" => Ok(Self::Oauth),
            "signed_post" => Ok(Self::SignedPost),
            "dns_record" => Ok(Self::DnsRecord),
            "challenge_response" => Ok(Self::ChallengeResponse),
            other => Err(format!(
                "invalid verification method: {other}; expected 'oauth', \
                 'signed_post', 'dns_record', or 'challenge_response'"
            )),
        }
    }
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

    /// Returns the recommended renewal interval in seconds for this method.
    #[must_use]
    pub const fn renewal_interval_secs(self) -> u64 {
        self.renewal_interval_days() as u64 * SECS_PER_DAY
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

    /// Returns the attestation class for this verification method (§7.4.1).
    ///
    /// - **Cryptographic** methods (OAuth, challenge-response) produce proofs
    ///   backed by cryptographic verification (OAuth JWTs verified against JWKS,
    ///   challenge-response signatures). Can be verified without re-fetching the
    ///   original external resource.
    /// - **Reference** methods (signed post, DNS record) require fetching or
    ///   validating external platform data that may become unavailable.
    #[must_use]
    pub const fn attestation_class(self) -> AttestationClass {
        match self {
            Self::Oauth | Self::ChallengeResponse => AttestationClass::Cryptographic,
            Self::SignedPost | Self::DnsRecord => AttestationClass::Reference,
        }
    }
}

// ---------------------------------------------------------------------------
// AttestationProof (§3.5.2)
// ---------------------------------------------------------------------------

/// Typed proof data for an identity link attestation (§3.5.2).
///
/// Each variant corresponds to one [`VerificationMethod`] and carries only the
/// fields relevant to that method. The `type` tag in the JSON/msgpack wire
/// format discriminates variants using `snake_case` names.
///
/// # Variant–method correspondence
///
/// | Variant                      | VerificationMethod   |
/// |------------------------------|----------------------|
/// | `OauthVerified`              | `Oauth`              |
/// | `SignedPostVerified`         | `SignedPost`         |
/// | `DnsRecordVerified`          | `DnsRecord`          |
/// | `ChallengeResponseVerified`  | `ChallengeResponse`  |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AttestationProof {
    /// OAuth 2.0 verification proof (§3.5.2).
    ///
    /// Contains the provider name, the platform-specific subject ID returned
    /// by the OAuth provider, and the verification timestamp (seconds).
    OauthVerified {
        /// OAuth provider identifier (e.g., `"github.com"`, `"google.com"`).
        provider: String,
        /// Platform-specific user/subject ID from the OAuth token.
        subject_id: String,
        /// Unix timestamp (seconds) when the OAuth verification occurred.
        verified_at: u64,
    },

    /// Signed post verification proof (§3.5.2).
    ///
    /// The user posted a message containing their DID and a nonce on the
    /// target platform. Verifiers fetch the post to confirm authorship.
    SignedPostVerified {
        /// Full URL of the post containing the DID and nonce.
        post_url: String,
        /// Random nonce included in the post to prevent replay.
        nonce: String,
        /// Unix timestamp (seconds) when the post was created.
        posted_at: u64,
    },

    /// DNS TXT record verification proof (§3.5.2).
    ///
    /// The user added a TXT record at `_scp-verify.<domain>` containing
    /// their DID. Verifiers perform a DNS lookup to confirm.
    DnsRecordVerified {
        /// Domain where the TXT record was placed.
        domain: String,
        /// DNS record name (e.g., `"_scp-verify"`).
        record_name: String,
    },

    /// Challenge-response verification proof (§3.5.2).
    ///
    /// A verifier sent a challenge through the platform; the user signed it
    /// with their SCP identity key.
    ChallengeResponseVerified {
        /// The challenge string sent by the verifier.
        challenge: String,
        /// Ed25519 signature over the challenge, hex-encoded.
        response_signature: String,
    },
}

impl AttestationProof {
    /// Returns the [`VerificationMethod`] that this proof variant corresponds to.
    ///
    /// This is the inverse of the variant–method mapping: given a proof, you
    /// can determine which verification method produced it.
    #[must_use]
    pub const fn expected_method(&self) -> VerificationMethod {
        match self {
            Self::OauthVerified { .. } => VerificationMethod::Oauth,
            Self::SignedPostVerified { .. } => VerificationMethod::SignedPost,
            Self::DnsRecordVerified { .. } => VerificationMethod::DnsRecord,
            Self::ChallengeResponseVerified { .. } => VerificationMethod::ChallengeResponse,
        }
    }

    /// Returns the [`AttestationClass`] for this proof type.
    ///
    /// Delegates to the corresponding [`VerificationMethod::attestation_class`].
    #[must_use]
    pub const fn attestation_class(&self) -> AttestationClass {
        self.expected_method().attestation_class()
    }
}

// ---------------------------------------------------------------------------
// AttestationClaim (§3.5.1)
// ---------------------------------------------------------------------------

/// The claim portion of an identity link attestation (§3.5.1).
///
/// Records which external platform identity is being claimed by the issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
/// Contains the verification method, proof data, the timestamp of
/// last verification, and an optional third-party verifier DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// Verification method used to establish the link.
    pub method: VerificationMethod,

    /// Method-specific proof data as an OPAQUE STRING (spec §3.5.2).
    ///
    /// Verifiers MUST use this string as-is in signature scope — do not parse
    /// and re-serialize. Three reasons:
    /// 1. Forward compatibility — new methods without wire format changes
    /// 2. Cross-implementation determinism — no serialization ambiguity
    /// 3. No parsing requirement — verifiers only need Ed25519 signature check
    pub proof: String,

    /// Unix timestamp (seconds) of last verification.
    pub verified_at: u64,

    /// DID of the third-party verifier, if the evidence was verified by
    /// someone other than the attestation issuer (e.g., challenge-response).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_did: Option<DID>,
}

impl AttestationEvidence {
    /// Returns whether this evidence has expired relative to the given
    /// current timestamp (seconds), based on the verification method's renewal interval.
    ///
    /// An evidence record is considered expired when
    /// `now_secs - verified_at > method.renewal_interval_secs()`.
    #[must_use]
    pub const fn is_expired(&self, now_secs: u64) -> bool {
        now_secs.saturating_sub(self.verified_at) > self.method.renewal_interval_secs()
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

    /// Unix timestamp (seconds) when the attestation was created.
    pub issued_at: u64,

    /// Optional expiry timestamp (seconds). If absent, valid until revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// The platform identity being claimed.
    pub claim: AttestationClaim,

    /// Evidence supporting the claim.
    pub evidence: AttestationEvidence,

    /// Revocation status: `Active` or `Revoked` (§7.4.1). Included in
    /// the signed scope to prevent replay of revoked attestations.
    pub revocation_status: crate::trust::attestation::RevocationStatus,

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
    pub fn is_time_expired(&self, now_secs: u64) -> bool {
        self.expires_at.is_some_and(|exp| now_secs > exp)
    }

    /// Returns whether the evidence needs renewal based on the verification
    /// method's recommended interval (§3.5.2).
    #[must_use]
    pub const fn needs_renewal(&self, now_secs: u64) -> bool {
        self.evidence.is_expired(now_secs)
    }

    /// Returns the renewal deadline (seconds) — the timestamp after
    /// which this attestation's evidence is considered stale.
    #[must_use]
    pub const fn renewal_deadline_secs(&self) -> u64 {
        self.evidence
            .verified_at
            .saturating_add(self.evidence.method.renewal_interval_secs())
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
    /// `evidence` (`MessagePack`), `revocation_status` (`MessagePack`).
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
    /// `evidence`, `revocation_status`) are serialized as `MessagePack` bytes
    /// and included as variable-length fields.
    ///
    /// This method is deterministic: identical attestation data always produces
    /// identical bytes, regardless of serde field ordering.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationSignatureError::SerializationFailed`] if any
    /// sub-struct (`claim`, `evidence`, `revocation_status`) cannot be serialized
    /// to `MessagePack`.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>, AttestationSignatureError> {
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
        let revocation_status_bytes =
            rmp_serde::to_vec_named(&self.revocation_status).map_err(|e| {
                AttestationSignatureError::SerializationFailed(format!(
                    "revocation_status serialization failed: {e}"
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
                CanonicalField::VarBytes(&revocation_status_bytes),
            ],
        )
        .map_err(|e| {
            AttestationSignatureError::SerializationFailed(format!("canonical hash failed: {e}"))
        })?
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
    /// - If revoked, `revoked_by` equals `issuer` (§7.4.1: only the issuer
    ///   can revoke their own attestation).
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

        // §7.4.1: only the issuer can revoke their own attestation.
        // Defense in depth — signature verification prevents tampering, but
        // structural validation catches malformed attestations early.
        if let crate::trust::attestation::RevocationStatus::Revoked { revoked_by, .. } =
            &self.revocation_status
            && *revoked_by != self.issuer
        {
            errors.push(Cow::Owned(format!(
                "revoked_by {} does not match issuer {}",
                revoked_by, self.issuer,
            )));
        }

        // expires_at, when present, must be after issued_at.
        if let Some(expires_at) = self.expires_at
            && expires_at <= self.issued_at
        {
            errors.push(Cow::Owned(format!(
                "expires_at ({expires_at}) must be greater than issued_at ({})",
                self.issued_at,
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
// §3.5.4 verification seam
// ---------------------------------------------------------------------------

/// Fragment of a DID document verification method that may sign an identity
/// link attestation (spec §3.5.2: "the issuer's `#active` or `#agent` key").
pub const SIGNING_FRAGMENT_ACTIVE: &str = "active";

/// Second admissible signing fragment (§3.5.2), used by an agent acting for
/// its human under a shared DID (ADR-039 §agent key).
pub const SIGNING_FRAGMENT_AGENT: &str = "agent";

/// What a consumer did about a Class 2 (Reference) proof resource before
/// calling [`verify_identity_link_attestation`].
///
/// Spec §3.5.4 gives Class 2 attestations — `SignedPost` and `DnsRecord` — a
/// verification step that no pure function can perform: fetch the post URL or
/// query the DNS TXT record and confirm that record carries an issuer's DID.
/// So a caller states the outcome of that fetch, and
/// [`verify_identity_link_attestation`] holds a caller to it. §3.5.0 forbids a
/// consumer from granting trust weight to an unfetched Reference attestation:
/// "An unverified Reference attestation is equivalent to no attestation."
///
/// A Class 1 (Cryptographic) attestation — `Oauth` and `ChallengeResponse` —
/// has no external proof resource, so
/// [`verify_identity_link_attestation`] ignores this value for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceProofOutcome {
    /// A consumer fetched a resource named by `evidence.proof` and confirmed
    /// an issuer's DID appears in that resource (§3.5.4 Class 2 step 2).
    Confirmed,

    /// A consumer performed no fetch. §3.5.4 Class 2 step 3 then leaves an
    /// attestation unverified, so [`verify_identity_link_attestation`] rejects
    /// a Class 2 attestation with
    /// [`IdentityLinkVerifyError::ReferenceProofUnverified`].
    NotFetched,
}

/// Whether an attestation's evidence still sits inside a renewal interval
/// (spec §3.5.4 step 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityLinkFreshness {
    /// `evidence.verified_at` is newer than a renewal interval that
    /// [`VerificationMethod::renewal_interval_secs`] gives for an
    /// attestation's method.
    Fresh,

    /// `evidence.verified_at` is older than that renewal interval. §3.5.4
    /// step 5 degrades a stale attestation — a consumer lowers its trust
    /// weight — and does NOT reject it.
    Stale {
        /// Unix timestamp (seconds) after which evidence became stale.
        renewal_deadline_secs: u64,
    },
}

/// What [`verify_identity_link_attestation`] establishes when every §3.5.4
/// check passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityLinkVerified {
    /// Which fragment of an issuer's DID document published a key that
    /// verified a signature: [`SIGNING_FRAGMENT_ACTIVE`] or
    /// [`SIGNING_FRAGMENT_AGENT`].
    pub signing_key_fragment: &'static str,

    /// Ed25519 public key bytes that verified a signature, taken from an
    /// issuer's resolved DID document — never from a caller.
    pub signing_public_key: [u8; 32],

    /// Evidence freshness per §3.5.4 step 5.
    pub freshness: IdentityLinkFreshness,
}

/// Why [`verify_identity_link_attestation`] rejected an attestation.
///
/// Each variant names one §3.5.4 step. A caller that maps every variant onto a
/// single `false` loses that distinction, so a caller which reports a reason to
/// a human reports this error rather than a boolean.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityLinkVerifyError {
    /// [`IdentityLinkAttestation::validate_structure`] reported errors, so an
    /// attestation contradicts its own §3.5.2 wire format before any key is
    /// consulted.
    #[error("attestation failed structural validation: {0}")]
    StructurallyInvalid(String),

    /// A resolved DID document identifies a different DID than an
    /// attestation's `issuer` names. §3.5.4 step 1 resolves *an issuer's*
    /// document, so a document for anyone else proves nothing about this
    /// attestation.
    #[error("resolved DID document identifies {document_id}, attestation issuer is {issuer}")]
    IssuerDocumentMismatch {
        /// `id` of a document a caller supplied.
        document_id: String,
        /// `issuer` an attestation names.
        issuer: String,
    },

    /// An issuer's document publishes neither an `#active` nor an `#agent`
    /// verification method whose key decodes to 32 Ed25519 bytes and whose
    /// `controller` is that issuer. §3.5.4 step 1 has no key to hand step 2.
    #[error(
        "resolved DID document for {issuer} publishes no usable #active or #agent \
         verification method"
    )]
    SigningKeyNotPublished {
        /// `issuer` an attestation names.
        issuer: String,
    },

    /// §3.5.4 step 2: no key an issuer's document publishes verifies an
    /// attestation's signature.
    #[error("signature verifies under no key the issuer's DID document publishes")]
    SignatureInvalid,

    /// §3.5.4 step 3: `revocation_status` reads `Revoked`.
    #[error("attestation was revoked at {revoked_at}")]
    Revoked {
        /// Unix timestamp (seconds) a revoker recorded.
        revoked_at: u64,
    },

    /// §3.5.4 step 4: `expires_at` has passed.
    #[error("attestation expired at {expires_at}; now is {now_secs}")]
    Expired {
        /// `expires_at` an attestation carries.
        expires_at: u64,
        /// Timestamp a caller supplied.
        now_secs: u64,
    },

    /// A Class 2 (Reference) attestation reached this function with
    /// [`ReferenceProofOutcome::NotFetched`]. §3.5.0 states that an unverified
    /// Reference attestation is equivalent to no attestation, so a caller that
    /// cannot fetch a proof resource gets a rejection rather than a passing
    /// result that overstates what a signature alone proves.
    #[error(
        "class 2 (reference) attestation carries method {method}, whose proof resource \
         no caller fetched; spec §3.5.4 leaves it unverified"
    )]
    ReferenceProofUnverified {
        /// Wire-format name of a verification method (§3.5.2).
        method: &'static str,
    },
}

/// Inputs [`verify_identity_link_attestation`] needs, as one flat record.
///
/// A flat named-field record rather than five positional arguments, per
/// `.docs/standards/construction.md` and ADR-052, the unified construction
/// pattern: an LLM author names each field at a call site, so a swapped
/// argument becomes a compile error rather than a silent security change.
#[derive(Debug, Clone, Copy)]
pub struct IdentityLinkVerifyInput<'a> {
    /// Attestation a consumer received.
    pub attestation: &'a IdentityLinkAttestation,

    /// DID document a consumer resolved for `attestation.issuer` — §3.5.4
    /// step 1. A consumer resolves this document itself; passing a document a
    /// holder supplied returns a holder's own claim to that holder.
    pub issuer_document: &'a scp_did::DidDocument,

    /// Current Unix time in seconds, for §3.5.4 steps 4 and 5.
    pub now_secs: u64,

    /// Outcome of a Class 2 proof fetch — see [`ReferenceProofOutcome`].
    pub reference_proof: ReferenceProofOutcome,
}

/// Runs spec §3.5.4 verification of an identity link attestation.
///
/// Pure, deterministic, side-effect-free, and wasm-safe: it performs no DID
/// resolution, no network request, and no clock read. A caller resolves an
/// issuer's DID document (§3.5.4 step 1), reads a clock, and states what it did
/// about a Class 2 proof resource; this function performs every remaining
/// check. That split mirrors
/// `scp_mls::keypackage_attestation::verify_attestation_with_resolution`, which
/// keeps the same core reusable by an in-browser client (ADR-057).
///
/// # Checks, in order
///
/// 1. **Structure** — [`IdentityLinkAttestation::validate_structure`] must
///    report no errors.
/// 2. **Document binding** — `issuer_document.id` must equal
///    `attestation.issuer`. Without this comparison a caller could hand over
///    any document and satisfy step 3 with a key from an unrelated identity.
/// 3. **Signing key (§3.5.4 step 1)** — collect `#active` and `#agent`
///    verification methods whose `controller` is an issuer and whose
///    `publicKeyMultibase` decodes to 32 Ed25519 bytes.
/// 4. **Signature (§3.5.4 step 2)** — an attestation's signature must verify
///    under one of those keys. §3.5.2 admits either fragment, so both are
///    tried and a fragment that verified is reported back.
/// 5. **Revocation (§3.5.4 step 3)** — `revocation_status` must read `Active`.
/// 6. **Expiry (§3.5.4 step 4)** — `expires_at`, when present, must not have
///    passed.
/// 7. **Class 2 proof (§3.5.4 Class 2 steps 2–3)** — a `SignedPost` or
///    `DnsRecord` attestation needs [`ReferenceProofOutcome::Confirmed`].
/// 8. **Freshness (§3.5.4 step 5)** — evidence older than a method's renewal
///    interval yields [`IdentityLinkFreshness::Stale`], which is a degraded
///    pass, not a rejection.
///
/// §3.5.4 step 6 asks a consumer to trust a self-attestation once steps 1–5
/// pass, and step 1's `issuer == subject` rule is checked inside
/// `validate_structure`, so this function returns success rather than asking a
/// caller for a further decision.
///
/// # Errors
///
/// Returns [`IdentityLinkVerifyError`] for a first failing check in that order.
pub fn verify_identity_link_attestation(
    input: &IdentityLinkVerifyInput<'_>,
) -> Result<IdentityLinkVerified, IdentityLinkVerifyError> {
    let attestation = input.attestation;

    // --- 1. Structure.
    let structural_errors = attestation.validate_structure();
    if !structural_errors.is_empty() {
        return Err(IdentityLinkVerifyError::StructurallyInvalid(
            structural_errors.join("; "),
        ));
    }

    // --- 2. Document binding. A document for anyone other than an issuer
    // proves nothing about this attestation, so compare before reading a key.
    let issuer_str: &str = (*attestation.issuer).as_ref();
    if input.issuer_document.id != issuer_str {
        return Err(IdentityLinkVerifyError::IssuerDocumentMismatch {
            document_id: input.issuer_document.id.clone(),
            issuer: issuer_str.to_owned(),
        });
    }

    // --- 3. Signing keys published by an issuer's document (§3.5.4 step 1).
    let mut candidates: Vec<(&'static str, [u8; 32])> = Vec::with_capacity(2);
    for fragment in [SIGNING_FRAGMENT_ACTIVE, SIGNING_FRAGMENT_AGENT] {
        let Some(method) = input
            .issuer_document
            .verification_method_by_fragment(fragment)
        else {
            continue;
        };
        // §18.2.2A binds a verification method to its controller. A document
        // that lists a method controlled by someone else does not authorize
        // that key to speak for this issuer.
        if method.controller != issuer_str {
            continue;
        }
        let Ok(key) = scp_did::decode_multibase_key(&method.public_key_multibase) else {
            continue;
        };
        candidates.push((fragment, key));
    }
    if candidates.is_empty() {
        return Err(IdentityLinkVerifyError::SigningKeyNotPublished {
            issuer: issuer_str.to_owned(),
        });
    }

    // --- 4. Signature (§3.5.4 step 2).
    let verified_with = candidates
        .into_iter()
        .find(|(_, key)| attestation.verify_signature(key).is_ok())
        .ok_or(IdentityLinkVerifyError::SignatureInvalid)?;
    let (signing_key_fragment, signing_public_key) = verified_with;

    // --- 5. Revocation (§3.5.4 step 3).
    if let crate::trust::attestation::RevocationStatus::Revoked { revoked_at, .. } =
        &attestation.revocation_status
    {
        return Err(IdentityLinkVerifyError::Revoked {
            revoked_at: *revoked_at,
        });
    }

    // --- 6. Expiry (§3.5.4 step 4).
    if let Some(expires_at) = attestation.expires_at
        && attestation.is_time_expired(input.now_secs)
    {
        return Err(IdentityLinkVerifyError::Expired {
            expires_at,
            now_secs: input.now_secs,
        });
    }

    // --- 7. Class 2 proof resource (§3.5.4 Class 2 steps 2–3).
    if attestation.evidence.method.attestation_class() == AttestationClass::Reference
        && input.reference_proof == ReferenceProofOutcome::NotFetched
    {
        return Err(IdentityLinkVerifyError::ReferenceProofUnverified {
            method: attestation.evidence.method.as_str(),
        });
    }

    // --- 8. Freshness (§3.5.4 step 5) — degrade, never reject.
    let freshness = if attestation.needs_renewal(input.now_secs) {
        IdentityLinkFreshness::Stale {
            renewal_deadline_secs: attestation.renewal_deadline_secs(),
        }
    } else {
        IdentityLinkFreshness::Fresh
    };

    Ok(IdentityLinkVerified {
        signing_key_fragment,
        signing_public_key,
        freshness,
    })
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
        let issued_at = 1_700_000_000_u64;

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
                proof: r#"{"type":"oauth_verified","provider":"github.com","subject_id":"12345","verified_at":1700000000}"#.to_owned(),
                verified_at: 1_700_000_000,
                verifier_did: None,
            },
            revocation_status: crate::trust::attestation::RevocationStatus::Active,
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
    fn verification_method_renewal_secs() {
        assert_eq!(
            VerificationMethod::Oauth.renewal_interval_secs(),
            30 * SECS_PER_DAY
        );
        assert_eq!(
            VerificationMethod::DnsRecord.renewal_interval_secs(),
            180 * SECS_PER_DAY
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
            proof: r#"{"type":"oauth_verified","provider":"github.com","subject_id":"12345","verified_at":1700000000}"#.to_owned(),
            verified_at: 1_700_000_000,
            verifier_did: None,
        };
        // 15 days later — within 30-day renewal
        let now = 1_700_000_000 + 15 * SECS_PER_DAY;
        assert!(!evidence.is_expired(now));
    }

    #[test]
    fn attestation_evidence_expired() {
        let evidence = AttestationEvidence {
            method: VerificationMethod::Oauth,
            proof: r#"{"type":"oauth_verified","provider":"github.com","subject_id":"12345","verified_at":1700000000}"#.to_owned(),
            verified_at: 1_700_000_000,
            verifier_did: None,
        };
        // 31 days later — past 30-day renewal
        let now = 1_700_000_000 + 31 * SECS_PER_DAY;
        assert!(evidence.is_expired(now));
    }

    #[test]
    fn attestation_evidence_exactly_at_boundary() {
        let evidence = AttestationEvidence {
            method: VerificationMethod::SignedPost,
            proof: r#"{"type":"signed_post_verified","post_url":"https://x.com/alice/123","nonce":"abc123","posted_at":1700000000}"#.to_owned(),
            verified_at: 1_700_000_000,
            verifier_did: None,
        };
        // Exactly at 90 days — not expired (boundary is >)
        let now = 1_700_000_000 + 90 * SECS_PER_DAY;
        assert!(!evidence.is_expired(now));
    }

    #[test]
    fn attestation_evidence_serialization_roundtrip() {
        let evidence = AttestationEvidence {
            method: VerificationMethod::ChallengeResponse,
            proof: r#"{"type":"challenge_response_verified","challenge":"abc","response_signature":"def"}"#.to_owned(),
            verified_at: 1_700_000_000,
            verifier_did: Some(did("did:dht:z6MkVerifier")),
        };
        let json = serde_json::to_string(&evidence).unwrap();
        let deserialized: AttestationEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, deserialized);
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
    fn attestation_validate_structure_revoked_by_non_issuer() {
        let mut attestation = make_attestation();
        attestation.revocation_status = crate::trust::attestation::RevocationStatus::Revoked {
            revoked_at: 1_700_000_100_000,
            reason: String::new(),
            revoked_by: did("did:dht:z6MkMallory"),
        };
        let errors = attestation.validate_structure();
        assert!(
            errors.iter().any(|e| e.contains("revoked_by")),
            "expected revoked_by mismatch error, got: {errors:?}",
        );
    }

    #[test]
    fn attestation_validate_structure_revoked_by_issuer_ok() {
        let mut attestation = make_attestation();
        attestation.revocation_status = crate::trust::attestation::RevocationStatus::Revoked {
            revoked_at: 1_700_000_100_000,
            reason: String::new(),
            revoked_by: attestation.issuer.clone(),
        };
        let errors = attestation.validate_structure();
        // No revoked_by error — only issuer can revoke.
        assert!(
            !errors.iter().any(|e| e.contains("revoked_by")),
            "unexpected revoked_by error: {errors:?}",
        );
    }

    #[test]
    fn attestation_is_time_expired_no_expiry() {
        let attestation = make_attestation();
        assert!(!attestation.is_time_expired(u64::MAX));
    }

    #[test]
    fn attestation_is_time_expired_before_expiry() {
        let mut attestation = make_attestation();
        attestation.expires_at = Some(2_000_000_000);
        assert!(!attestation.is_time_expired(1_999_999_999));
    }

    #[test]
    fn attestation_is_time_expired_after_expiry() {
        let mut attestation = make_attestation();
        attestation.expires_at = Some(2_000_000_000);
        assert!(attestation.is_time_expired(2_000_000_001));
    }

    #[test]
    fn attestation_needs_renewal_fresh() {
        let attestation = make_attestation();
        // 5 days later — well within 30-day OAuth renewal
        let now = attestation.evidence.verified_at + 5 * SECS_PER_DAY;
        assert!(!attestation.needs_renewal(now));
    }

    #[test]
    fn attestation_needs_renewal_stale() {
        let attestation = make_attestation();
        // 31 days later — past 30-day OAuth renewal
        let now = attestation.evidence.verified_at + 31 * SECS_PER_DAY;
        assert!(attestation.needs_renewal(now));
    }

    #[test]
    fn attestation_renewal_deadline_secs() {
        let attestation = make_attestation();
        let expected = attestation.evidence.verified_at + 30 * SECS_PER_DAY;
        assert_eq!(attestation.renewal_deadline_secs(), expected);
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
        attestation.expires_at = Some(1_800_000_000);
        let json = serde_json::to_string(&attestation).unwrap();
        assert!(json.contains("1800000000"));
        let deserialized: IdentityLinkAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expires_at, Some(1_800_000_000));
    }

    #[test]
    fn attestation_dns_record_method_renewal() {
        let mut attestation = make_attestation();
        attestation.evidence.method = VerificationMethod::DnsRecord;
        // 100 days — within 180-day DNS renewal
        let now = attestation.evidence.verified_at + 100 * SECS_PER_DAY;
        assert!(!attestation.needs_renewal(now));
        // 181 days — past renewal
        let now = attestation.evidence.verified_at + 181 * SECS_PER_DAY;
        assert!(attestation.needs_renewal(now));
    }

    // -----------------------------------------------------------------------
    // Forward compatibility: unknown fields ignored (§13.5.1, #593)
    // -----------------------------------------------------------------------

    #[test]
    fn attestation_ignores_unknown_fields_json() {
        let attestation = make_attestation();
        let mut json: serde_json::Value = serde_json::to_value(&attestation).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("future_field".to_owned(), serde_json::Value::Bool(true));
        let result = serde_json::from_value::<IdentityLinkAttestation>(json);
        assert!(
            result.is_ok(),
            "wire-format types must ignore unknown fields per §13.5.1: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn attestation_claim_ignores_unknown_fields() {
        let claim = AttestationClaim::new(
            "github.com".to_owned(),
            "alice".to_owned(),
            Some("12345".to_owned()),
        );
        let mut map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::to_value(&claim).unwrap()).unwrap();
        map.insert("future_field".into(), "v2-data".into());
        let result = serde_json::from_value::<AttestationClaim>(serde_json::Value::Object(map));
        assert!(
            result.is_ok(),
            "wire-format types must ignore unknown fields per §13.5.1: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.platform, "github.com");
        assert_eq!(decoded.platform_handle, "alice");
    }

    #[test]
    fn attestation_evidence_ignores_unknown_fields() {
        let evidence = AttestationEvidence {
            method: VerificationMethod::Oauth,
            proof: r#"{"type":"oauth_verified","provider":"github.com","subject_id":"12345","verified_at":1700000000}"#.to_owned(),
            verified_at: 1_700_000_000_000,
            verifier_did: None,
        };
        let mut map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::to_value(&evidence).unwrap()).unwrap();
        map.insert("future_field".into(), serde_json::json!(42));
        let result = serde_json::from_value::<AttestationEvidence>(serde_json::Value::Object(map));
        assert!(
            result.is_ok(),
            "wire-format types must ignore unknown fields per §13.5.1: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.method, VerificationMethod::Oauth);
        assert_eq!(decoded.verified_at, 1_700_000_000_000);
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
                proof: r#"{"type":"oauth_verified","provider":"github.com","subject_id":"12345","verified_at":1700000000}"#.to_owned(),
                verified_at: 1_700_000_000_000,
                verifier_did: None,
            },
            revocation_status: crate::trust::attestation::RevocationStatus::Active,
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
    fn verify_signature_tampered_revocation_status() {
        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        // Tamper revocation_status from Active to Revoked — must invalidate
        attestation.revocation_status = crate::trust::attestation::RevocationStatus::Revoked {
            revoked_at: 1_700_000_000_000,
            reason: "tampered".to_owned(),
            revoked_by: attestation.issuer.clone(),
        };
        let vk = sk.verifying_key();
        let result = attestation.verify_signature(vk.as_bytes());
        assert!(
            result.is_err(),
            "should fail with tampered revocation_status"
        );
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
                proof: r#"{"type":"signed_post_verified","post_url":"https://x.com/alice/123","nonce":"abc","posted_at":1700000000}"#.to_owned(),
                verified_at: 1_700_000_000_000,
                verifier_did: None,
            },
            revocation_status: crate::trust::attestation::RevocationStatus::Active,
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

    // -----------------------------------------------------------------------
    // AttestationClass
    // -----------------------------------------------------------------------

    #[test]
    fn attestation_class_from_verification_method() {
        assert_eq!(
            VerificationMethod::Oauth.attestation_class(),
            AttestationClass::Cryptographic
        );
        assert_eq!(
            VerificationMethod::ChallengeResponse.attestation_class(),
            AttestationClass::Cryptographic
        );
        assert_eq!(
            VerificationMethod::SignedPost.attestation_class(),
            AttestationClass::Reference
        );
        assert_eq!(
            VerificationMethod::DnsRecord.attestation_class(),
            AttestationClass::Reference
        );
    }

    #[test]
    fn attestation_class_serialization_roundtrip() {
        let classes = [AttestationClass::Cryptographic, AttestationClass::Reference];
        for class in &classes {
            let json = serde_json::to_string(class).unwrap();
            let deserialized: AttestationClass = serde_json::from_str(&json).unwrap();
            assert_eq!(class, &deserialized);
        }
    }

    #[test]
    fn attestation_class_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&AttestationClass::Cryptographic).unwrap(),
            "\"cryptographic\""
        );
        assert_eq!(
            serde_json::to_string(&AttestationClass::Reference).unwrap(),
            "\"reference\""
        );
    }

    // -----------------------------------------------------------------------
    // AttestationProof (deprecated — kept for SDK-side parsing tests)
    // -----------------------------------------------------------------------

    #[allow(deprecated)]
    #[test]
    fn attestation_proof_expected_method() {
        let oauth = AttestationProof::OauthVerified {
            provider: "g".to_owned(),
            subject_id: "1".to_owned(),
            verified_at: 0,
        };
        assert_eq!(oauth.expected_method(), VerificationMethod::Oauth);

        let signed_post = AttestationProof::SignedPostVerified {
            post_url: "u".to_owned(),
            nonce: "n".to_owned(),
            posted_at: 0,
        };
        assert_eq!(
            signed_post.expected_method(),
            VerificationMethod::SignedPost
        );

        let dns = AttestationProof::DnsRecordVerified {
            domain: "d".to_owned(),
            record_name: "r".to_owned(),
        };
        assert_eq!(dns.expected_method(), VerificationMethod::DnsRecord);

        let cr = AttestationProof::ChallengeResponseVerified {
            challenge: "c".to_owned(),
            response_signature: "s".to_owned(),
        };
        assert_eq!(cr.expected_method(), VerificationMethod::ChallengeResponse);
    }

    #[allow(deprecated)]
    #[test]
    fn attestation_proof_attestation_class() {
        let oauth = AttestationProof::OauthVerified {
            provider: "g".to_owned(),
            subject_id: "1".to_owned(),
            verified_at: 0,
        };
        assert_eq!(oauth.attestation_class(), AttestationClass::Cryptographic);

        let dns = AttestationProof::DnsRecordVerified {
            domain: "d".to_owned(),
            record_name: "r".to_owned(),
        };
        assert_eq!(dns.attestation_class(), AttestationClass::Reference);
    }

    #[allow(deprecated)]
    #[test]
    fn attestation_proof_serialization_roundtrip_all_variants() {
        let proofs = [
            AttestationProof::OauthVerified {
                provider: "github.com".to_owned(),
                subject_id: "12345".to_owned(),
                verified_at: 1_700_000_000,
            },
            AttestationProof::SignedPostVerified {
                post_url: "https://x.com/alice/123".to_owned(),
                nonce: "abc123".to_owned(),
                posted_at: 1_700_000_000,
            },
            AttestationProof::DnsRecordVerified {
                domain: "example.com".to_owned(),
                record_name: "_scp-verify".to_owned(),
            },
            AttestationProof::ChallengeResponseVerified {
                challenge: "random-challenge".to_owned(),
                response_signature: "deadbeef".to_owned(),
            },
        ];

        for proof in &proofs {
            // JSON roundtrip
            let json = serde_json::to_string(proof).unwrap();
            let deserialized: AttestationProof = serde_json::from_str(&json).unwrap();
            assert_eq!(proof, &deserialized, "JSON roundtrip failed for {proof:?}");

            // MessagePack roundtrip
            let bytes = rmp_serde::to_vec_named(proof).unwrap();
            let deserialized: AttestationProof = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(
                proof, &deserialized,
                "MessagePack roundtrip failed for {proof:?}"
            );
        }
    }

    #[allow(deprecated)]
    #[test]
    fn attestation_proof_json_has_type_tag() {
        let proof = AttestationProof::OauthVerified {
            provider: "github.com".to_owned(),
            subject_id: "12345".to_owned(),
            verified_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&proof).unwrap();
        assert!(
            json.contains("\"type\":\"oauth_verified\""),
            "expected type tag in JSON: {json}"
        );

        let proof = AttestationProof::DnsRecordVerified {
            domain: "example.com".to_owned(),
            record_name: "_scp-verify".to_owned(),
        };
        let json = serde_json::to_string(&proof).unwrap();
        assert!(
            json.contains("\"type\":\"dns_record_verified\""),
            "expected type tag in JSON: {json}"
        );
    }

    // -----------------------------------------------------------------------
    // Proof is opaque string — no proof-method validation
    // -----------------------------------------------------------------------

    #[test]
    fn validate_structure_does_not_check_proof_content() {
        // Proof is an opaque string per §3.5.2. validate_structure does not
        // inspect its content, even if it doesn't match the method.
        let mut attestation = make_attestation();
        attestation.evidence.proof = "arbitrary-non-json-string".to_owned();
        let errors = attestation.validate_structure();
        assert!(
            !errors.iter().any(|e| e.contains("proof")),
            "validate_structure must not inspect proof content: {errors:?}"
        );
    }

    // -----------------------------------------------------------------------
    // §3.5.4 verification seam
    // -----------------------------------------------------------------------

    /// Timestamp every seam test reads as "now" — equal to the `issued_at` and
    /// `verified_at` that `make_signed_attestation` stamps, so evidence is
    /// fresh unless a test moves this forward.
    const SEAM_NOW: u64 = 1_700_000_000_000;

    /// Builds a DID document for `did_str` publishing `active_key` at
    /// `#active`, and `agent_key` at `#agent` when supplied.
    fn seam_document(
        did_str: &str,
        active_key: &[u8; 32],
        agent_key: Option<&[u8; 32]>,
    ) -> scp_did::DidDocument {
        let identity_key = test_signing_key(0x11).verifying_key().to_bytes();
        let commitment = [0u8; 32];
        scp_did::DidDocument::new_with_agent_key(
            did_str,
            &identity_key,
            active_key,
            &commitment,
            agent_key.map(<[u8; 32]>::as_slice),
        )
    }

    /// Runs the seam with a Class 1 posture (no reference proof to fetch).
    fn run_seam(
        attestation: &IdentityLinkAttestation,
        document: &scp_did::DidDocument,
        now_secs: u64,
    ) -> Result<IdentityLinkVerified, IdentityLinkVerifyError> {
        verify_identity_link_attestation(&IdentityLinkVerifyInput {
            attestation,
            issuer_document: document,
            now_secs,
            reference_proof: ReferenceProofOutcome::NotFetched,
        })
    }

    #[test]
    fn seam_accepts_signature_by_the_active_key_the_document_publishes() {
        let sk = test_signing_key(0xAA);
        let attestation = make_signed_attestation(&sk);
        let doc = seam_document(
            (*attestation.issuer).as_ref(),
            &sk.verifying_key().to_bytes(),
            None,
        );

        let verified = run_seam(&attestation, &doc, SEAM_NOW).expect("seam must accept");
        assert_eq!(verified.signing_key_fragment, SIGNING_FRAGMENT_ACTIVE);
        assert_eq!(verified.signing_public_key, sk.verifying_key().to_bytes());
        assert_eq!(verified.freshness, IdentityLinkFreshness::Fresh);
    }

    /// Regression pin for GitHub issue #2335 finding 2: an attacker's key plus
    /// an attacker's attestation used to return `true`, because a bridge took
    /// a verifying key from its caller. A key that an issuer's DID document
    /// does not publish now fails §3.5.4 step 2.
    #[test]
    fn seam_rejects_an_attacker_key_paired_with_an_attacker_attestation() {
        let attacker = test_signing_key(0xBB);
        let attestation = make_signed_attestation(&attacker);

        // An issuer's real document publishes a different `#active` key.
        let honest = test_signing_key(0xAA);
        let doc = seam_document(
            (*attestation.issuer).as_ref(),
            &honest.verifying_key().to_bytes(),
            None,
        );

        assert_eq!(
            run_seam(&attestation, &doc, SEAM_NOW),
            Err(IdentityLinkVerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn seam_rejects_a_document_that_identifies_a_different_did() {
        let sk = test_signing_key(0xAA);
        let attestation = make_signed_attestation(&sk);
        let doc = seam_document(
            "did:dht:z6MkSomebodyElse",
            &sk.verifying_key().to_bytes(),
            None,
        );

        assert!(matches!(
            run_seam(&attestation, &doc, SEAM_NOW),
            Err(IdentityLinkVerifyError::IssuerDocumentMismatch { .. })
        ));
    }

    #[test]
    fn seam_accepts_a_signature_by_the_agent_key() {
        let agent = test_signing_key(0xCD);
        let attestation = make_signed_attestation(&agent);
        let active = test_signing_key(0xAA);
        let doc = seam_document(
            (*attestation.issuer).as_ref(),
            &active.verifying_key().to_bytes(),
            Some(&agent.verifying_key().to_bytes()),
        );

        let verified = run_seam(&attestation, &doc, SEAM_NOW).expect("agent key must verify");
        assert_eq!(verified.signing_key_fragment, SIGNING_FRAGMENT_AGENT);
    }

    #[test]
    fn seam_ignores_a_verification_method_another_did_controls() {
        let sk = test_signing_key(0xAA);
        let attestation = make_signed_attestation(&sk);
        let mut doc = seam_document(
            (*attestation.issuer).as_ref(),
            &sk.verifying_key().to_bytes(),
            None,
        );
        for method in &mut doc.verification_method {
            if method.id.ends_with("#active") {
                method.controller = "did:dht:z6MkAttacker".to_owned();
            }
        }

        assert!(matches!(
            run_seam(&attestation, &doc, SEAM_NOW),
            Err(IdentityLinkVerifyError::SigningKeyNotPublished { .. })
        ));
    }

    #[test]
    fn seam_rejects_a_revoked_attestation() {
        use ed25519_dalek::Signer;

        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        attestation.revocation_status = crate::trust::attestation::RevocationStatus::Revoked {
            reason: "user revoked".to_owned(),
            revoked_at: SEAM_NOW - 10,
            revoked_by: attestation.issuer.clone(),
        };
        let canonical = attestation.canonical_signing_bytes().unwrap();
        attestation.signature = sk.sign(&canonical).to_bytes().to_vec();

        let doc = seam_document(
            (*attestation.issuer).as_ref(),
            &sk.verifying_key().to_bytes(),
            None,
        );

        assert_eq!(
            run_seam(&attestation, &doc, SEAM_NOW),
            Err(IdentityLinkVerifyError::Revoked {
                revoked_at: SEAM_NOW - 10
            })
        );
    }

    #[test]
    fn seam_rejects_an_expired_attestation() {
        use ed25519_dalek::Signer;

        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        attestation.expires_at = Some(SEAM_NOW + 100);
        let canonical = attestation.canonical_signing_bytes().unwrap();
        attestation.signature = sk.sign(&canonical).to_bytes().to_vec();

        let doc = seam_document(
            (*attestation.issuer).as_ref(),
            &sk.verifying_key().to_bytes(),
            None,
        );

        assert_eq!(
            run_seam(&attestation, &doc, SEAM_NOW + 200),
            Err(IdentityLinkVerifyError::Expired {
                expires_at: SEAM_NOW + 100,
                now_secs: SEAM_NOW + 200,
            })
        );
    }

    #[test]
    fn seam_rejects_a_class_2_attestation_whose_proof_nobody_fetched() {
        use ed25519_dalek::Signer;

        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        attestation.evidence.method = VerificationMethod::SignedPost;
        let canonical = attestation.canonical_signing_bytes().unwrap();
        attestation.signature = sk.sign(&canonical).to_bytes().to_vec();

        let doc = seam_document(
            (*attestation.issuer).as_ref(),
            &sk.verifying_key().to_bytes(),
            None,
        );

        assert_eq!(
            run_seam(&attestation, &doc, SEAM_NOW),
            Err(IdentityLinkVerifyError::ReferenceProofUnverified {
                method: "signed_post"
            })
        );
    }

    #[test]
    fn seam_accepts_a_class_2_attestation_whose_proof_a_consumer_confirmed() {
        use ed25519_dalek::Signer;

        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        attestation.evidence.method = VerificationMethod::SignedPost;
        let canonical = attestation.canonical_signing_bytes().unwrap();
        attestation.signature = sk.sign(&canonical).to_bytes().to_vec();

        let doc = seam_document(
            (*attestation.issuer).as_ref(),
            &sk.verifying_key().to_bytes(),
            None,
        );

        let verified = verify_identity_link_attestation(&IdentityLinkVerifyInput {
            attestation: &attestation,
            issuer_document: &doc,
            now_secs: SEAM_NOW,
            reference_proof: ReferenceProofOutcome::Confirmed,
        })
        .expect("a confirmed reference proof must pass");
        assert_eq!(verified.freshness, IdentityLinkFreshness::Fresh);
    }

    #[test]
    fn seam_degrades_stale_evidence_rather_than_rejecting_it() {
        let sk = test_signing_key(0xAA);
        let attestation = make_signed_attestation(&sk);
        let doc = seam_document(
            (*attestation.issuer).as_ref(),
            &sk.verifying_key().to_bytes(),
            None,
        );

        // OAuth's renewal interval is 30 days; step one second past it.
        let past_deadline = attestation.renewal_deadline_secs() + 1;
        let verified = run_seam(&attestation, &doc, past_deadline)
            .expect("§3.5.4 step 5 degrades, not rejects");
        assert_eq!(
            verified.freshness,
            IdentityLinkFreshness::Stale {
                renewal_deadline_secs: attestation.renewal_deadline_secs(),
            }
        );
    }

    #[test]
    fn seam_rejects_a_structurally_invalid_attestation_before_reading_a_key() {
        let sk = test_signing_key(0xAA);
        let mut attestation = make_signed_attestation(&sk);
        attestation.subject = did("did:dht:z6MkNotTheIssuer");

        let doc = seam_document(
            (*attestation.issuer).as_ref(),
            &sk.verifying_key().to_bytes(),
            None,
        );

        assert!(matches!(
            run_seam(&attestation, &doc, SEAM_NOW),
            Err(IdentityLinkVerifyError::StructurallyInvalid(_))
        ));
    }
}
