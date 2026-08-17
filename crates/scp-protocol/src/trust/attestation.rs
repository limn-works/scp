//! Attestation verification and freshness checking.
//!
//! Implements the common attestation envelope (ADR-017, Spec section 7.4.1)
//! with generic verification logic and interoperable attestation exchange.
//!
//! # Verification
//!
//! [`verify_attestation`] checks an attestation's Ed25519 signature against the
//! issuer's public key (resolved via DID), validates evidence per attestation
//! type, checks expiry, and queries revocation status.
//!
//! # Freshness
//!
//! [`check_attestation_freshness`] evaluates the renewal interval. Stale
//! attestations (past renewal interval but not expired) are degraded, not
//! revoked. Returns [`FreshnessStatus::Fresh`], [`FreshnessStatus::Stale`], or
//! [`FreshnessStatus::Expired`].
//!
//! # Threshold Attestation
//!
//! [`check_threshold_attestation`] counts attestations of a given type from an
//! attestor set and verifies independence: shared context memberships and mutual
//! endorsements reduce the independence score.
//!
//! See ADR-017 in `.docs/adrs/phase-4.md`.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::identity::attestation::AttestationClass;
use scp_clock::Clock;
use scp_crypto::verify_ed25519_signature;
use scp_did::DID;
use scp_event_log::Ed25519Signature;

use super::{AttestationType, TrustError};

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

/// Common attestation envelope (ADR-017, Spec section 7.4.1).
///
/// All attestation types share this envelope format, enabling generic
/// verification logic and interoperable attestation exchange. The `claim` field
/// carries type-specific data as a JSON value.
///
/// See ADR-017 acceptance criteria 1, 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Unique attestation identifier.
    pub id: String,
    /// The type of attestation.
    pub attestation_type: AttestationType,
    /// DID of the attestation issuer.
    pub issuer: DID,
    /// DID of the attestation subject.
    pub subject: DID,
    /// Type-specific claim data.
    ///
    /// Serialized into the signed preimage as RFC 8785 (JCS) canonical JSON
    /// (§9.5.2). **I-JSON numeric constraint (RFC 7493):** numeric values in
    /// the claim MUST be within the IEEE-754 double exactly-representable
    /// integer range (|n| ≤ 2^53); larger identifiers (e.g. 64-bit snowflake
    /// IDs, u64 counters) MUST be string-encoded by the caller. RFC 8785
    /// serializes numbers as ES6 doubles, so integers beyond 2^53 are not
    /// injective: distinct values in the same rounding class canonicalize to
    /// identical bytes, and a signature over one such claim validly covers
    /// every other claim in that class.
    pub claim: serde_json::Value,
    /// Optional evidence supporting the attestation.
    pub evidence: Option<AttestationEvidence>,
    /// Unix timestamp (seconds) when the attestation was issued.
    pub issued_at: u64,
    /// Optional expiry timestamp (seconds).
    pub expires_at: Option<u64>,
    /// Optional renewal interval. Attestations past this interval but not
    /// expired are considered stale (degraded, not revoked).
    ///
    /// # ADVISORY / UNAUTHENTICATED
    ///
    /// This field is **NOT** part of the signed attestation preimage
    /// ([`canonical_attestation_bytes`] excludes it, per §9.5.2), so the
    /// issuer's signature does **not** cover it. It is advisory metadata only.
    /// A holder or relay can change it in transit without invalidating the
    /// signature, so a verifier MUST NOT treat it as an authenticated input to
    /// any authenticity or freshness *security* decision. Freshness derived
    /// from it (see `renewal.rs`) is a soft/degraded-status signal, not an
    /// authenticity guarantee. Authenticated staleness bounds come only from
    /// the signed `issued_at` / `expires_at` fields. (Design: attestations are
    /// renewable "without re-sign" — see `renewal.rs` — so this exclusion is
    /// intentional; the security consequence is documented here rather than
    /// closed by signing it, which would be a wire-format/model change.)
    pub renewal_interval: Option<Duration>,
    /// Timestamp (seconds) of the last renewal, if renewable (spec 7.4.1).
    ///
    /// When present, freshness is measured from `renewed_at` instead of
    /// `issued_at`. A renewable attestation that has never been renewed
    /// should set this to `None`, causing freshness to be measured from
    /// `issued_at`.
    ///
    /// # ADVISORY / UNAUTHENTICATED
    ///
    /// Like [`Self::renewal_interval`], this field is **NOT** in the signed
    /// preimage ([`canonical_attestation_bytes`] excludes it) and is therefore
    /// unauthenticated. A holder/relay can bump it to make a stale attestation
    /// read as freshly renewed, and no verifier can detect the change from the
    /// signature. A verifier MUST NOT trust it for an authenticity or freshness
    /// *security* decision; treat renewal-derived freshness as advisory only.
    pub renewed_at: Option<u64>,
    /// Current revocation status.
    pub revocation_status: RevocationStatus,
    /// Ed25519 signature over the attestation content.
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// AttestationEvidence
// ---------------------------------------------------------------------------

/// Evidence supporting an attestation claim.
///
/// The structure of evidence depends on the attestation type. For example,
/// a `OutletIntegrity` attestation might include a hash of the outlet binary,
/// while an `IdentityLink` attestation might include a signed challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// The type of evidence (e.g., "hash", "signed-challenge", "log-reference").
    pub evidence_type: String,
    /// Evidence data. Interpretation depends on `evidence_type`.
    pub data: serde_json::Value,
}

// ---------------------------------------------------------------------------
// IdentityLinkClaim
// ---------------------------------------------------------------------------

/// Typed claim for `AttestationType::IdentityLink` attestations (spec §3.5, §7.4.2).
///
/// "Identity link. Issuer attests they control an external platform identity.
/// Evidence: platform-specific proof (OAuth, signed post, DNS record)."
///
/// This struct provides a typed wire format for the identity link claim that
/// would otherwise be an untyped `serde_json::Value` in [`Attestation::claim`].
/// An `IdentityLinkClaim` can be serialized to/from JSON for use in the
/// `claim` field of an [`Attestation`] with
/// `attestation_type: AttestationType::IdentityLink`.
///
/// See spec §3.5 (Identity Attestations) and §7.4.2 (Attestation Types).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityLinkClaim {
    /// The external platform name (e.g., `"x"`, `"github"`, `"google"`).
    pub platform: String,
    /// The user's handle or identifier on the external platform.
    pub platform_handle: String,
    /// The verification method used to prove ownership of the external
    /// identity (e.g., `"oauth"`, `"signed-post"`, `"dns-record"`).
    pub verification_method: String,
    /// URL or reference to the verification proof, if publicly accessible
    /// (e.g., a signed post URL, DNS TXT record location).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_url: Option<String>,
}

impl IdentityLinkClaim {
    /// Serialize this claim to a `serde_json::Value` for use in [`Attestation::claim`].
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails (should not happen for this type).
    pub fn to_claim_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    /// Deserialize an `IdentityLinkClaim` from the `claim` field of an [`Attestation`].
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON value does not match the expected structure.
    pub fn from_claim_value(value: &serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value.clone())
    }
}

// ---------------------------------------------------------------------------
// RevocationStatus
// ---------------------------------------------------------------------------

/// Revocation status of an attestation (§7.4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationStatus {
    /// The attestation is active and not revoked.
    Active,
    /// The attestation has been revoked.
    Revoked {
        /// Unix timestamp (seconds) when the revocation occurred.
        revoked_at: u64,
        /// Reason for revocation (empty string if no reason provided).
        #[serde(default, deserialize_with = "deserialize_string_or_null")]
        reason: String,
        /// DID that performed the revocation. Must equal the attestation's
        /// issuer — only the issuer can revoke their own attestation (§7.4.1).
        #[serde(default = "default_revoked_by")]
        revoked_by: DID,
    },
}

/// Deserializes a `String` field that may be `null` in JSON. Returns the string
/// value when present, or an empty string for both missing keys and explicit
/// `null` values. `#[serde(default)]` alone only handles missing keys — an
/// explicit `"reason": null` would fail deserialization without this.
fn deserialize_string_or_null<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Option::unwrap_or_default)
}

/// Default `revoked_by` DID for pre-migration attestations that were serialized
/// without the `revoked_by` field.
fn default_revoked_by() -> DID {
    DID::from("did:unknown:pre-migration")
}

// ---------------------------------------------------------------------------
// FreshnessStatus
// ---------------------------------------------------------------------------

/// Result of attestation freshness evaluation.
///
/// Stale attestations (past renewal interval but not expired) are degraded,
/// not revoked. This allows agents to make nuanced trust decisions based on
/// how recently an attestation was renewed.
///
/// See ADR-017 acceptance criterion 8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshnessStatus {
    /// The attestation is within its renewal interval (or has no renewal
    /// interval set).
    Fresh,
    /// The attestation is past its renewal interval but not yet expired.
    Stale {
        /// Unix timestamp (seconds) since when the attestation has been stale.
        since: u64,
    },
    /// The attestation has expired (past `expires_at`).
    Expired,
}

// ---------------------------------------------------------------------------
// ThresholdRequirement
// ---------------------------------------------------------------------------

/// N-of-M threshold requirement for attestation verification.
///
/// Specifies how many attestors (`required_count`) out of a total
/// (`total_attestors`) must provide attestations of a given type, and the
/// minimum independence score required among those attestors.
///
/// All `f64` fields must be finite (not NaN or infinity). Value ranges are
/// enforced: `independence_threshold` must be in \[0.0, 1.0\], penalty fields
/// must be non-negative, and `required_count` must be <= `total_attestors`.
/// Deserialization rejects invalid values via `TryFrom<ThresholdRequirementRaw>`.
///
/// Fields are private to prevent bypass of validation. Use [`ThresholdRequirement::new`]
/// or [`ThresholdRequirement::try_new`] for construction, and accessor methods for reading.
///
/// See ADR-017 acceptance criterion 7.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(into = "ThresholdRequirementRaw")]
pub struct ThresholdRequirement {
    /// The minimum number of valid attestations required (N).
    required_count: u32,
    /// The total number of attestors in the set (M).
    total_attestors: u32,
    /// Minimum independence score (0.0 to 1.0). Attestors with shared context
    /// memberships or mutual endorsements have reduced independence.
    independence_threshold: f64,
    /// Independence penalty per shared context membership between a pair of
    /// attestors. Default: 0.1. Capped at `shared_context_penalty_cap` total.
    shared_context_penalty: f64,
    /// Maximum total penalty from shared context memberships for a single
    /// pair. Default: 0.5.
    shared_context_penalty_cap: f64,
    /// Independence penalty per mutual endorsement direction (A endorsed B
    /// = one direction, B endorsed A = another). Default: 0.2.
    mutual_endorsement_penalty: f64,
}

/// Raw deserialization helper for [`ThresholdRequirement`].
///
/// Carries `#[serde(default)]` annotations for backward-compatible
/// deserialization, then validates f64 fields via `TryFrom`.
#[derive(Deserialize, Serialize)]
struct ThresholdRequirementRaw {
    required_count: u32,
    total_attestors: u32,
    independence_threshold: f64,
    #[serde(default = "default_shared_context_penalty")]
    shared_context_penalty: f64,
    #[serde(default = "default_shared_context_penalty_cap")]
    shared_context_penalty_cap: f64,
    #[serde(default = "default_mutual_endorsement_penalty")]
    mutual_endorsement_penalty: f64,
}

impl From<ThresholdRequirement> for ThresholdRequirementRaw {
    fn from(t: ThresholdRequirement) -> Self {
        Self {
            required_count: t.required_count,
            total_attestors: t.total_attestors,
            independence_threshold: t.independence_threshold,
            shared_context_penalty: t.shared_context_penalty,
            shared_context_penalty_cap: t.shared_context_penalty_cap,
            mutual_endorsement_penalty: t.mutual_endorsement_penalty,
        }
    }
}

impl TryFrom<ThresholdRequirementRaw> for ThresholdRequirement {
    type Error = String;

    fn try_from(raw: ThresholdRequirementRaw) -> Result<Self, Self::Error> {
        let t = Self {
            required_count: raw.required_count,
            total_attestors: raw.total_attestors,
            independence_threshold: raw.independence_threshold,
            shared_context_penalty: raw.shared_context_penalty,
            shared_context_penalty_cap: raw.shared_context_penalty_cap,
            mutual_endorsement_penalty: raw.mutual_endorsement_penalty,
        };
        t.validate().map(|()| t)
    }
}

impl<'de> Deserialize<'de> for ThresholdRequirement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = ThresholdRequirementRaw::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

const fn default_shared_context_penalty() -> f64 {
    0.1
}

const fn default_shared_context_penalty_cap() -> f64 {
    0.5
}

const fn default_mutual_endorsement_penalty() -> f64 {
    0.2
}

impl ThresholdRequirement {
    /// Creates a new `ThresholdRequirement` with default penalty values.
    ///
    /// # Safety (logical)
    ///
    /// **This constructor performs NO validation.** It is `const` for use in
    /// static/const contexts (e.g., compile-time policy definitions). The caller
    /// MUST ensure:
    ///
    /// - `required_count <= total_attestors`
    /// - `independence_threshold` is in \[0.0, 1.0\] and finite
    /// - All f64 penalty fields (using defaults here) are finite and non-negative
    ///
    /// Violating these invariants will cause incorrect threshold evaluation at
    /// runtime. For runtime construction with validation, use
    /// [`ThresholdRequirement::try_new`] instead.
    #[must_use]
    pub const fn new(
        required_count: u32,
        total_attestors: u32,
        independence_threshold: f64,
    ) -> Self {
        Self {
            required_count,
            total_attestors,
            independence_threshold,
            shared_context_penalty: default_shared_context_penalty(),
            shared_context_penalty_cap: default_shared_context_penalty_cap(),
            mutual_endorsement_penalty: default_mutual_endorsement_penalty(),
        }
    }

    /// Creates a new `ThresholdRequirement` with explicit penalty values.
    ///
    /// Like [`ThresholdRequirement::new`], this is `const` and does not
    /// validate. For runtime construction with validation, use
    /// [`ThresholdRequirement::try_new_with_penalties`].
    ///
    /// Prefer [`ThresholdRequirement::new`] + [`ThresholdRequirement::try_new`]
    /// when default penalties suffice. This constructor is for advanced use
    /// cases that need custom penalty tuning.
    #[must_use]
    pub const fn new_with_penalties(
        required_count: u32,
        total_attestors: u32,
        independence_threshold: f64,
        shared_context_penalty: f64,
        shared_context_penalty_cap: f64,
        mutual_endorsement_penalty: f64,
    ) -> Self {
        Self {
            required_count,
            total_attestors,
            independence_threshold,
            shared_context_penalty,
            shared_context_penalty_cap,
            mutual_endorsement_penalty,
        }
    }

    /// Creates a new `ThresholdRequirement` with explicit penalty values and
    /// validation.
    ///
    /// # Errors
    ///
    /// Returns a description of the invalid field if validation fails.
    pub fn try_new_with_penalties(
        required_count: u32,
        total_attestors: u32,
        independence_threshold: f64,
        shared_context_penalty: f64,
        shared_context_penalty_cap: f64,
        mutual_endorsement_penalty: f64,
    ) -> Result<Self, String> {
        let t = Self::new_with_penalties(
            required_count,
            total_attestors,
            independence_threshold,
            shared_context_penalty,
            shared_context_penalty_cap,
            mutual_endorsement_penalty,
        );
        t.validate().map(|()| t)
    }

    /// Creates a new `ThresholdRequirement` with validation.
    ///
    /// Returns an error if any field violates its constraints: f64 fields must
    /// be finite, `independence_threshold` must be in \[0.0, 1.0\], penalty
    /// fields must be non-negative, and `required_count` must be <=
    /// `total_attestors`.
    ///
    /// # Errors
    ///
    /// Returns a description of the invalid field if validation fails.
    pub fn try_new(
        required_count: u32,
        total_attestors: u32,
        independence_threshold: f64,
    ) -> Result<Self, String> {
        let t = Self::new(required_count, total_attestors, independence_threshold);
        t.validate().map(|()| t)
    }

    /// Validates all field constraints.
    ///
    /// - All f64 fields must be finite (not NaN or infinity).
    /// - `independence_threshold` must be in \[0.0, 1.0\].
    /// - `shared_context_penalty`, `shared_context_penalty_cap`, and
    ///   `mutual_endorsement_penalty` must be non-negative.
    /// - `required_count` must be <= `total_attestors`.
    ///
    /// # Errors
    ///
    /// Returns a description of the first invalid field found.
    pub fn validate(&self) -> Result<(), String> {
        // Check finiteness first (catches NaN and infinity).
        let fields: &[(&str, f64)] = &[
            ("independence_threshold", self.independence_threshold),
            ("shared_context_penalty", self.shared_context_penalty),
            (
                "shared_context_penalty_cap",
                self.shared_context_penalty_cap,
            ),
            (
                "mutual_endorsement_penalty",
                self.mutual_endorsement_penalty,
            ),
        ];
        for &(name, value) in fields {
            if !value.is_finite() {
                return Err(format!(
                    "ThresholdRequirement::{name} must be finite, got {value}"
                ));
            }
        }

        // independence_threshold must be in [0.0, 1.0].
        if !(0.0..=1.0).contains(&self.independence_threshold) {
            return Err(format!(
                "ThresholdRequirement::independence_threshold must be in [0.0, 1.0], got {}",
                self.independence_threshold
            ));
        }

        // Penalty fields must be non-negative.
        if self.shared_context_penalty < 0.0 {
            return Err(format!(
                "ThresholdRequirement::shared_context_penalty must be non-negative, got {}",
                self.shared_context_penalty
            ));
        }
        if self.shared_context_penalty_cap < 0.0 {
            return Err(format!(
                "ThresholdRequirement::shared_context_penalty_cap must be non-negative, got {}",
                self.shared_context_penalty_cap
            ));
        }
        if self.mutual_endorsement_penalty < 0.0 {
            return Err(format!(
                "ThresholdRequirement::mutual_endorsement_penalty must be non-negative, got {}",
                self.mutual_endorsement_penalty
            ));
        }

        // required_count must be <= total_attestors.
        if self.required_count > self.total_attestors {
            return Err(format!(
                "ThresholdRequirement::required_count ({}) must be <= total_attestors ({})",
                self.required_count, self.total_attestors
            ));
        }

        Ok(())
    }

    // --- Accessor methods ---

    /// Returns the minimum number of valid attestations required (N).
    #[must_use]
    pub const fn required_count(&self) -> u32 {
        self.required_count
    }

    /// Returns the total number of attestors in the set (M).
    #[must_use]
    pub const fn total_attestors(&self) -> u32 {
        self.total_attestors
    }

    /// Returns the minimum independence score (0.0 to 1.0).
    #[must_use]
    pub const fn independence_threshold(&self) -> f64 {
        self.independence_threshold
    }

    /// Returns the independence penalty per shared context membership.
    #[must_use]
    pub const fn shared_context_penalty(&self) -> f64 {
        self.shared_context_penalty
    }

    /// Returns the maximum total penalty from shared context memberships.
    #[must_use]
    pub const fn shared_context_penalty_cap(&self) -> f64 {
        self.shared_context_penalty_cap
    }

    /// Returns the independence penalty per mutual endorsement direction.
    #[must_use]
    pub const fn mutual_endorsement_penalty(&self) -> f64 {
        self.mutual_endorsement_penalty
    }
}

// ---------------------------------------------------------------------------
// ThresholdResult
// ---------------------------------------------------------------------------

/// Result of a threshold attestation check.
///
/// Reports whether the N-of-M threshold was met and whether the attestors
/// have sufficient independence.
#[derive(Debug, Clone)]
pub struct ThresholdResult {
    /// Whether the threshold requirement is fully satisfied (count met and
    /// independence sufficient).
    pub met: bool,
    /// Number of valid attestations found.
    pub valid_count: u32,
    /// The required count (N).
    pub required_count: u32,
    /// Computed independence score (0.0 to 1.0).
    pub independence_score: f64,
    /// The required independence threshold.
    pub independence_threshold: f64,
}

// ---------------------------------------------------------------------------
// AttestorInfo
// ---------------------------------------------------------------------------

/// Information about an attestor used for independence scoring.
///
/// Callers provide this for each attestor in the set so that
/// [`check_threshold_attestation`] can evaluate shared context memberships
/// and mutual endorsements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestorInfo {
    /// The DID of the attestor.
    pub did: DID,
    /// Context IDs the attestor is a member of.
    pub context_memberships: HashSet<String>,
    /// DIDs that this attestor has endorsed (mutual endorsements reduce
    /// independence).
    pub endorsements: HashSet<DID>,
    /// The attestation provided by this attestor (if any). Only attestations
    /// matching the required type are considered.
    pub attestation: Option<Attestation>,
}

// ---------------------------------------------------------------------------
// DID resolver trait
// ---------------------------------------------------------------------------

/// Resolves a DID to its Ed25519 public key bytes.
///
/// Used by [`verify_attestation`] to obtain the issuer's public key for
/// signature verification. Implementations may resolve via DHT, cache, or
/// test fixtures.
///
/// # Totality invariant (REQUIRED)
///
/// An `Err` from [`Self::resolve_public_key`] MUST mean a **terminal** outcome:
/// the key genuinely cannot exist for that DID, or the DID is malformed —
/// i.e., verification against it can never succeed and never will. An `Err`
/// MUST NOT signal a **transient** condition (network timeout, cache miss,
/// resolver temporarily unavailable). Callers on the trust read path (e.g.
/// `trust::aggregate`) treat `Err` as "verification genuinely failed" and
/// **discard** the attestation; a transient error surfaced as `Err` would
/// silently erase a live attestation from the trust computation — a fail-open
/// availability bug for trust evidence.
///
/// A resolver that cannot honor this invariant (a networked/fallible DHT or
/// cache-backed resolver) MUST NOT be wired into the aggregate read path
/// without first splitting terminal from transient errors there. The
/// production [`IdentityDidPublicKeyResolver`] satisfies the invariant by
/// construction: it is a pure, deterministic DID-string parse with no I/O.
pub trait DidPublicKeyResolver {
    /// Resolves a DID string to its Ed25519 public key bytes (32 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the DID cannot be resolved. Per the trait's
    /// totality invariant, an `Err` MUST be terminal (key cannot exist /
    /// malformed DID), never a retryable transient failure.
    fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError>;
}

// ---------------------------------------------------------------------------
// IdentityDidPublicKeyResolver — production implementation
// ---------------------------------------------------------------------------

/// Production [`DidPublicKeyResolver`] that resolves public keys from DID
/// strings using `scp-identity`.
///
/// For `did:dht:z...` DIDs, extracts the Ed25519 public key embedded in the
/// DID string itself (the identity key, verification method `#0`).
///
/// For `did:key:` DIDs (only accepted when `scp-core/testing` feature is
/// enabled), decodes the hex-encoded key.
///
/// This resolver does NOT perform full DID document resolution (DHT lookup,
/// relay query, cache check). It extracts the identity key directly from the
/// DID string, so it answers every call with `#0`.
///
/// **The citation this doc comment carried does not support that, and a spec
/// clause contradicts it.** It read "the identity key (`#0`) is the canonical
/// signing key for attestations per ADR-017". ADR-017 in
/// `.docs/adrs/phase-4.md` states one relevant line — "Verifies Ed25519
/// signature against issuer's public key (resolved via DID)" — and names no
/// verification method. §9.5.2 of the security-model spec names one, and
/// excludes this resolver's answer: a `KeyPackageAttestation` "is signed by the
/// DID verification method named in `signing_key_id` (field 6, `#active` or
/// `#agent` — never `#0`)". §3.5.2 of the identity spec says the same for an
/// identity link attestation.
///
/// A `did:dht` string is z-base-32 of an Identity Key, so this resolver
/// verifies an attestation against the one method those clauses exclude, and a
/// rotated `#active` or `#agent` key can never be withdrawn from it. Shipped
/// callers reach it at `crates/scp-ffi/common/src/trust_store.rs` and through
/// the `UniFFI` bridge.
///
/// A fix routes those callers through
/// `scp_ffi_common::resolvers::IdentityBackedDidResolver`, whose
/// `DidPublicKeyResolver` implementation resolves `#active` under
/// `assertionMethod`. It needs a ruling first: this type's own name and doc
/// assert an `#0` rule that no artifact states, and whoever wrote them may have
/// had a reason no artifact records.
///
/// For use cases that require resolving the active signing key (`#active`) or
/// agent key (`#agent`), callers should use the full DID resolution pipeline
/// in `scp-identity` directly.
pub struct IdentityDidPublicKeyResolver;

impl DidPublicKeyResolver for IdentityDidPublicKeyResolver {
    fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
        // Delegates to the canonical implementation in scp-did which
        // supports did:dht:z (production) and did:key:{hex} (testing only,
        // gated behind #[cfg(test)] / feature = "testing"). See issue #128.
        let key = scp_did::extract_public_key_from_did(did).map_err(|e| {
            TrustError::AttestationSignatureInvalid {
                attestation_id: String::new(),
                reason: format!("failed to extract public key from DID {did}: {e}"),
            }
        })?;
        Ok(key.to_vec())
    }
}

// ---------------------------------------------------------------------------
// AttestationRevocationChecker trait (§7.4.1)
// ---------------------------------------------------------------------------

/// Trait for checking attestation revocation status.
///
/// Implementations may check DID document service endpoints, local revocation
/// lists, or external revocation services. The trait is object-safe and
/// designed for injection into [`verify_attestation`].
///
/// See spec §7.4.1 (attestation verification).
pub trait AttestationRevocationChecker {
    /// Checks if the attestation with the given ID has been revoked by the issuer.
    ///
    /// Returns `Some(revoked_at)` with the revocation timestamp (seconds) if the
    /// attestation has been revoked, or `None` if the attestation is still active.
    fn check_revocation(&self, attestation_id: &str, issuer: &DID) -> Option<u64>;
}

/// No-op revocation checker that always returns `None` (not revoked).
///
/// Suitable for testing, offline verification, or contexts where external
/// revocation checking is not available.
pub struct NoOpRevocationChecker;

impl AttestationRevocationChecker for NoOpRevocationChecker {
    fn check_revocation(&self, _attestation_id: &str, _issuer: &DID) -> Option<u64> {
        None
    }
}

// ---------------------------------------------------------------------------
// AttestationVerificationCache (§7.4.1)
// ---------------------------------------------------------------------------

/// TTL for cached Reference attestation verification results: 1 hour.
///
/// Reference attestations (signed post, DNS record) depend on external platform data
/// that can change or disappear. Shorter TTL ensures freshness.
pub const REFERENCE_TTL_SECS: u64 = 3600;

/// TTL for cached Cryptographic attestation verification results: 24 hours.
///
/// Cryptographic attestations (OAuth, challenge-response) are self-verifiable
/// and change infrequently. Longer TTL reduces redundant verification.
pub const CRYPTOGRAPHIC_TTL_SECS: u64 = 86400;

/// A cached attestation verification result.
struct VerificationCacheEntry {
    /// When the verification was performed (seconds since epoch).
    verified_at: u64,
    /// The class of the attestation, determining the TTL.
    attestation_class: AttestationClass,
    /// The cached verification result.
    result: Result<(), TrustError>,
}

/// Cache for attestation verification results with class-based TTLs (§7.4.1).
///
/// Per-class TTLs: [`REFERENCE_TTL_SECS`] (1 hour) for Reference attestations,
/// [`CRYPTOGRAPHIC_TTL_SECS`] (24 hours) for Cryptographic attestations.
///
/// This is a simple in-memory cache keyed by attestation ID. It does not
/// persist across process restarts. For persistent caching, use
/// [`super::aggregate::AttestationCache`] backed by a
/// [`super::aggregate::TrustProtocolRepository`].
pub struct AttestationVerificationCache {
    entries: HashMap<String, VerificationCacheEntry>,
    /// Maximum number of entries the cache can hold. When full, the oldest
    /// entry (by `verified_at`) is evicted before inserting a new one.
    max_capacity: usize,
}

/// Default maximum capacity for the attestation verification cache.
const DEFAULT_CACHE_CAPACITY: usize = 10_000;

impl AttestationVerificationCache {
    /// Creates an empty verification cache with the default capacity (10000).
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_capacity: DEFAULT_CACHE_CAPACITY,
        }
    }

    /// Creates an empty verification cache with the specified maximum capacity.
    #[must_use]
    pub fn with_capacity(max_capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_capacity,
        }
    }

    /// Returns the TTL in seconds for the given attestation class.
    #[must_use]
    const fn ttl_for_class(class: AttestationClass) -> u64 {
        match class {
            AttestationClass::Reference => REFERENCE_TTL_SECS,
            AttestationClass::Cryptographic => CRYPTOGRAPHIC_TTL_SECS,
        }
    }

    /// Retrieves a cached verification result if the entry exists and has not
    /// expired.
    ///
    /// Returns `None` if the entry is missing or expired.
    #[must_use]
    pub fn get(&self, attestation_id: &str, now: u64) -> Option<&Result<(), TrustError>> {
        let entry = self.entries.get(attestation_id)?;
        let ttl = Self::ttl_for_class(entry.attestation_class);
        if now > entry.verified_at.saturating_add(ttl) {
            return None;
        }
        Some(&entry.result)
    }

    /// Inserts a verification result into the cache.
    ///
    /// Overwrites any existing entry for the same attestation ID. If the
    /// cache is at capacity and the key is new, evicts the oldest entry
    /// (by `verified_at` timestamp) before inserting.
    ///
    /// # Performance
    ///
    /// Eviction scans all entries to find the oldest (`O(n)` where `n` is
    /// the cache size). This is acceptable for the default capacity (10000)
    /// and typical usage patterns where eviction is infrequent. For larger
    /// caches, consider a `BTreeMap<(u64, String), _>` indexed by
    /// `(verified_at, id)` for `O(log n)` eviction.
    pub fn insert(
        &mut self,
        attestation_id: String,
        class: AttestationClass,
        result: Result<(), TrustError>,
        now: u64,
    ) {
        // A cache with max_capacity == 0 is effectively disabled.
        if self.max_capacity == 0 {
            return;
        }
        // If this key already exists, overwriting won't increase count.
        if !self.entries.contains_key(&attestation_id) && self.entries.len() >= self.max_capacity {
            // Evict the oldest entry by verified_at.
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.verified_at)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }
        self.entries.insert(
            attestation_id,
            VerificationCacheEntry {
                verified_at: now,
                attestation_class: class,
                result,
            },
        );
    }

    /// Removes all expired entries from the cache.
    pub fn evict_expired(&mut self, now: u64) {
        self.entries.retain(|_, entry| {
            let ttl = Self::ttl_for_class(entry.attestation_class);
            now <= entry.verified_at.saturating_add(ttl)
        });
    }
}

impl Default for AttestationVerificationCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// verify_attestation
// ---------------------------------------------------------------------------

/// Verifies an attestation's signature, evidence, expiry, and revocation status.
///
/// # Verification steps
///
/// 1. **Signature:** Verifies the Ed25519 signature against the issuer's public
///    key, resolved via the provided [`DidPublicKeyResolver`].
/// 2. **Evidence:** Validates that evidence is present when required by the
///    attestation type.
/// 3. **Expiry:** Rejects if `expires_at < now`.
/// 4. **Revocation (field):** Rejects if the attestation's `revocation_status`
///    field is `Revoked`.
/// 5. **Revocation (external):** If a [`AttestationRevocationChecker`] is
///    provided, queries it for external revocation signals. This is belt-and-
///    suspenders with step 4: the field may be stale while the checker queries
///    a live revocation service.
///
/// # Errors
///
/// Returns a specific [`TrustError`] variant for each failure mode:
/// - [`TrustError::AttestationSignatureInvalid`] for signature failures
/// - [`TrustError::AttestationExpired`] when past expiry
/// - [`TrustError::AttestationRevocationInvalid`] when `revoked_by` does not
///   match the issuer (§7.4.1)
/// - [`TrustError::AttestationRevoked`] when revoked by the issuer (field or external)
/// - [`TrustError::AttestationEvidenceInvalid`] when required evidence is
///   missing or invalid
///
/// See ADR-017 acceptance criteria 3-7.
pub fn verify_attestation(
    attestation: &Attestation,
    resolver: &(impl DidPublicKeyResolver + ?Sized),
    clock: &(impl Clock + ?Sized),
) -> Result<(), TrustError> {
    verify_attestation_with_revocation(attestation, resolver, clock, None)
}

/// Verifies an attestation with an optional external revocation checker.
///
/// This is the full-featured verification entry point. [`verify_attestation`]
/// delegates here with `revocation_checker: None` for backward compatibility.
///
/// See [`verify_attestation`] for the verification steps and error semantics.
///
/// # Errors
///
/// Returns a specific [`TrustError`] variant for each failure mode:
/// - [`TrustError::AttestationSignatureInvalid`] for signature failures
/// - [`TrustError::AttestationExpired`] when past expiry
/// - [`TrustError::AttestationRevoked`] when revoked (field or external checker)
/// - [`TrustError::AttestationEvidenceInvalid`] when required evidence is
///   missing or invalid
pub fn verify_attestation_with_revocation(
    attestation: &Attestation,
    resolver: &(impl DidPublicKeyResolver + ?Sized),
    clock: &(impl Clock + ?Sized),
    revocation_checker: Option<&dyn AttestationRevocationChecker>,
) -> Result<(), TrustError> {
    // 1. Verify Ed25519 signature against issuer's public key.
    let public_key_bytes = resolver.resolve_public_key(&attestation.issuer)?;
    let canonical = canonical_attestation_bytes(attestation)?;
    verify_ed25519_signature(&public_key_bytes, &canonical, &attestation.signature).map_err(
        |reason| TrustError::AttestationSignatureInvalid {
            attestation_id: attestation.id.clone(),
            reason,
        },
    )?;

    // 2. Validate evidence per attestation type.
    validate_evidence(attestation)?;

    // 3. Check expiry.
    let now = clock.now_secs();
    if let Some(expires_at) = attestation.expires_at
        && expires_at < now
    {
        return Err(TrustError::AttestationExpired {
            attestation_id: attestation.id.clone(),
            expired_at: expires_at,
        });
    }

    // 4. Check revocation status (field on the attestation itself).
    if let RevocationStatus::Revoked {
        revoked_at,
        revoked_by,
        ..
    } = &attestation.revocation_status
    {
        // Per §7.4.1, only the issuer can revoke their own attestation.
        if *revoked_by != attestation.issuer {
            return Err(TrustError::AttestationRevocationInvalid {
                attestation_id: attestation.id.clone(),
                revoked_by: revoked_by.to_string(),
                issuer: attestation.issuer.to_string(),
            });
        }
        return Err(TrustError::AttestationRevoked {
            attestation_id: attestation.id.clone(),
            revoked_at: *revoked_at,
        });
    }

    // 5. Check external revocation (belt-and-suspenders with step 4).
    if let Some(checker) = revocation_checker
        && let Some(revoked_at) = checker.check_revocation(&attestation.id, &attestation.issuer)
    {
        return Err(TrustError::AttestationRevoked {
            attestation_id: attestation.id.clone(),
            revoked_at,
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// check_attestation_freshness
// ---------------------------------------------------------------------------

/// Evaluates the freshness of an attestation based on its renewal interval.
///
/// - **Fresh:** Within the renewal interval (or no renewal interval set).
/// - **Stale:** Past the renewal interval but not expired. Stale attestations
///   are degraded, not revoked.
/// - **Expired:** Past `expires_at`.
///
/// See ADR-017 acceptance criterion 8.
pub fn check_attestation_freshness(
    attestation: &Attestation,
    clock: &impl Clock,
) -> FreshnessStatus {
    let now = clock.now_secs();

    // Check expiry first.
    if let Some(expires_at) = attestation.expires_at
        && now >= expires_at
    {
        return FreshnessStatus::Expired;
    }

    // Check renewal interval. When `renewed_at` is present, measure
    // freshness from the last renewal time, not the original issue time.
    // This ensures that renewed attestations are considered fresh per
    // spec section 7.3.6.
    if let Some(renewal_interval) = attestation.renewal_interval {
        let renewal_secs = renewal_interval.as_secs();
        let base_time = attestation.renewed_at.unwrap_or(attestation.issued_at);
        let renewal_deadline = base_time.saturating_add(renewal_secs);
        if now >= renewal_deadline {
            return FreshnessStatus::Stale {
                since: renewal_deadline,
            };
        }
    }

    FreshnessStatus::Fresh
}

// ---------------------------------------------------------------------------
// check_threshold_attestation
// ---------------------------------------------------------------------------

/// Checks whether an N-of-M threshold attestation requirement is met.
///
/// Counts attestations of the given type from the attestor set and verifies
/// independence. Shared context memberships and mutual endorsements reduce
/// the independence score.
///
/// # Independence scoring
///
/// For each pair of attestors that both have valid attestations, the algorithm
/// counts:
/// - Shared context memberships (contexts both attestors belong to).
/// - Mutual endorsements (attestor A endorsed B or B endorsed A).
///
/// Each shared context reduces the pair's independence by a fixed penalty.
/// Each mutual endorsement reduces it further. The overall independence score
/// is the average pairwise independence across all valid attestor pairs.
///
/// See ADR-017 acceptance criterion 7.
#[must_use]
pub fn check_threshold_attestation(
    attestation_type: &AttestationType,
    attestors: &[AttestorInfo],
    requirement: &ThresholdRequirement,
) -> ThresholdResult {
    // Defense-in-depth: validate requirement even though constructors enforce it.
    debug_assert!(
        requirement.validate().is_ok(),
        "ThresholdRequirement invariants violated: {:?}",
        requirement.validate()
    );

    // Count valid attestations of the required type.
    let valid_attestors: Vec<&AttestorInfo> = attestors
        .iter()
        .filter(|a| {
            a.attestation
                .as_ref()
                .is_some_and(|att| &att.attestation_type == attestation_type)
        })
        .collect();

    let valid_count = u32::try_from(valid_attestors.len()).unwrap_or(u32::MAX);

    // Compute independence score among valid attestors.
    let independence_score = compute_independence_score(
        &valid_attestors,
        requirement.shared_context_penalty(),
        requirement.shared_context_penalty_cap(),
        requirement.mutual_endorsement_penalty(),
    );

    let count_met = valid_count >= requirement.required_count();
    let independence_met = independence_score >= requirement.independence_threshold();

    ThresholdResult {
        met: count_met && independence_met,
        valid_count,
        required_count: requirement.required_count(),
        independence_score,
        independence_threshold: requirement.independence_threshold(),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Computes the canonical byte representation of an attestation for signing.
///
/// ```text
/// "SCP-ATTESTATION-V1:" || len(id) || id || attestation_type_tag_BE
///     || len(issuer) || issuer || len(subject) || subject
///     || len(claim_json) || claim_json || len(evidence_msgpack) || evidence_msgpack
///     || issued_at_BE || expires_at_BE || len(revocation_status_msgpack) || revocation_status_msgpack
/// ```
///
/// Variable-length fields are prefixed with their length as a 4-byte
/// big-endian u32 to prevent field-boundary ambiguity. The domain separator
/// prevents cross-protocol hash confusion. `attestation_type` uses a stable
/// numeric tag (u16 big-endian) instead of Debug formatting for
/// cross-version determinism. `issued_at` uses big-endian encoding,
/// consistent with all other canonical hash functions.
///
/// `revocation_status` is included in the signed scope so that an
/// intermediary cannot flip Active↔Revoked without invalidating the
/// signature.
///
/// # Authenticated field set (and what is intentionally excluded)
///
/// The signed preimage covers exactly: `id`, `attestation_type`, `issuer`,
/// `subject`, `claim`, `evidence`, `issued_at`, `expires_at`,
/// `revocation_status` (§9.5.2). The renewal fields
/// [`Attestation::renewal_interval`] and [`Attestation::renewed_at`] are
/// **deliberately excluded** so an attestation can be renewed without
/// re-signing (`renewal.rs`). Consequently those two fields are
/// **UNAUTHENTICATED / ADVISORY**: they are not covered by the issuer
/// signature, a holder/relay can alter them undetectably, and neither this
/// function nor any verifier treats them as an authenticated input to an
/// authenticity or freshness *security* decision. Only the fields listed above
/// are authenticated.
///
/// # Canonicalization scheme — per §9.5.2
///
/// The §9.5.2 Attestation table assigns a serialization per field:
///
/// - `claim` — **compact JSON** (no whitespace, equivalent to Python
///   `json.dumps(separators=(',', ':'))`), produced via [`crate::jcs::to_vec`]
///   (RFC 8785 JCS). JCS emits exactly that compact form and additionally
///   sorts object keys, which makes the preimage deterministic across
///   implementations. This matches how the same §9.5.2 "compact JSON" phrase
///   is implemented for `GovernanceProposal` `action_bytes`
///   (`compute_proposal_id`) and `SignedVote` `vote_type`
///   (`compute_vote_hash`).
/// - `evidence` and `revocation_status` — `rmp_serde::to_vec_named`
///   (`MessagePack`, named keys), as the §9.5.2 note explicitly sanctions for
///   these two fields.
///
/// Note: `IdentityLinkAttestation::canonical_signing_bytes` is governed by a
/// different spec row (§3 identity, domain
/// `SCP-IDENTITY-LINK-ATTESTATION-V1:`) which mandates `MessagePack` for its
/// `claim` as well — its scheme is independent of this function.
///
/// # I-JSON numeric constraint on `claim` (RFC 7493, per §9.5.2)
///
/// RFC 8785 serializes JSON numbers as ES6 IEEE-754 doubles, so claim
/// integers outside |n| ≤ 2^53 are **not injective**: distinct values in the
/// same f64 rounding class (e.g. `9007199254740993` and `9007199254740992`)
/// canonicalize to identical bytes, producing identical preimages — a
/// signature over one validly covers the other, and the substitution is
/// undetectable. Callers MUST keep claim numeric values within |n| ≤ 2^53 and
/// string-encode larger identifiers (snowflake IDs, u64 counters). This
/// function does not reject out-of-range integers — the coercion is inherent
/// to RFC 8785 and is pinned by test.
///
/// # Errors
///
/// Returns [`TrustError::CanonicalizationFailed`] if evidence, claim, or
/// revocation-status serialization fails, or if the canonical hash cannot be
/// constructed.
pub fn canonical_attestation_bytes(attestation: &Attestation) -> Result<Vec<u8>, TrustError> {
    use crate::crypto::canonical::{CanonicalField, canonical_hash};

    // Serialize evidence as MessagePack bytes (named/sorted keys) if present.
    let evidence_bytes = attestation
        .evidence
        .as_ref()
        .map(|e| {
            rmp_serde::to_vec_named(e).map_err(|err| TrustError::CanonicalizationFailed {
                reason: format!("evidence serialization failed: {err}"),
            })
        })
        .transpose()?;

    // Serialize revocation_status as MessagePack bytes (named/sorted keys).
    let revocation_bytes =
        rmp_serde::to_vec_named(&attestation.revocation_status).map_err(|err| {
            TrustError::CanonicalizationFailed {
                reason: format!("revocation_status serialization failed: {err}"),
            }
        })?;

    // Field order per §9.5.2: id, attestation_type, issuer, subject, claim,
    // evidence, issued_at, expires_at, revocation_status.
    //
    // Serialize claim as compact JSON per the §9.5.2 Attestation table
    // (row 5: "compact JSON", equivalent to Python
    // `json.dumps(separators=(',', ':'))`). RFC 8785 JCS produces exactly
    // that compact form with deterministic (sorted) key ordering — the same
    // implementation of the same spec phrase as `compute_proposal_id`
    // (`action_bytes`) and `compute_vote_hash` (`vote_type`).
    let claim_bytes = crate::jcs::to_vec(&attestation.claim).map_err(|err| {
        TrustError::CanonicalizationFailed {
            reason: format!("claim serialization failed: {err}"),
        }
    })?;
    Ok(canonical_hash(
        "SCP-ATTESTATION-V1:",
        &[
            CanonicalField::VarBytes(attestation.id.as_bytes()),
            CanonicalField::U16(super::attestation_type_tag(&attestation.attestation_type)),
            CanonicalField::VarBytes(attestation.issuer.as_bytes()),
            CanonicalField::VarBytes(attestation.subject.as_bytes()),
            CanonicalField::VarBytes(&claim_bytes),
            evidence_bytes
                .as_deref()
                .map_or(CanonicalField::Absent, CanonicalField::VarBytes),
            CanonicalField::U64(attestation.issued_at),
            attestation
                .expires_at
                .map_or(CanonicalField::Absent, CanonicalField::U64),
            CanonicalField::VarBytes(&revocation_bytes),
        ],
    )
    .map_err(|e| TrustError::CanonicalizationFailed {
        reason: format!("canonical hash failed: {e}"),
    })?
    .to_vec())
}

/// Validates that evidence is present and appropriate for the attestation type.
///
/// Some attestation types require evidence:
/// - `OutletIntegrity` requires evidence (hash of the outlet).
/// - `ParticipationWitness` requires evidence (log reference).
///
/// Other types accept optional evidence without strict requirements.
fn validate_evidence(attestation: &Attestation) -> Result<(), TrustError> {
    let requires_evidence = matches!(
        attestation.attestation_type,
        AttestationType::OutletIntegrity | AttestationType::ParticipationWitness
    );

    if requires_evidence && attestation.evidence.is_none() {
        return Err(TrustError::AttestationEvidenceInvalid {
            attestation_id: attestation.id.clone(),
            reason: format!(
                "{:?} attestations require evidence",
                attestation.attestation_type
            ),
        });
    }

    // If evidence is present, validate it has a non-empty type.
    if let Some(evidence) = &attestation.evidence
        && evidence.evidence_type.is_empty()
    {
        return Err(TrustError::AttestationEvidenceInvalid {
            attestation_id: attestation.id.clone(),
            reason: "evidence type must not be empty".to_owned(),
        });
    }

    Ok(())
}

/// Computes the independence score for a set of valid attestors.
///
/// Returns 1.0 for a single attestor or empty set (no pairs to compare).
/// For multiple attestors, averages the pairwise independence scores.
///
/// Each pair starts at 1.0 independence. Penalties are configurable via
/// [`ThresholdRequirement`]:
/// - `shared_context_penalty` per shared context (capped at `shared_context_penalty_cap`).
/// - `mutual_endorsement_penalty` per endorsement direction.
///
/// The pair independence is clamped to [0.0, 1.0].
fn compute_independence_score(
    attestors: &[&AttestorInfo],
    shared_context_penalty: f64,
    shared_context_penalty_cap: f64,
    mutual_endorsement_penalty: f64,
) -> f64 {
    // Clamp to non-negative: negative penalties would invert scoring,
    // making colluding attestors appear more independent.
    let shared_context_penalty = shared_context_penalty.max(0.0);
    let shared_context_penalty_cap = shared_context_penalty_cap.max(0.0);
    let mutual_endorsement_penalty = mutual_endorsement_penalty.max(0.0);

    if attestors.len() < 2 {
        return 1.0;
    }

    let mut total_pair_score = 0.0;
    let mut pair_count = 0u64;

    for i in 0..attestors.len() {
        for j in (i + 1)..attestors.len() {
            let a = attestors[i];
            let b = attestors[j];

            let mut pair_independence = 1.0;

            // Penalty for shared context memberships.
            let shared_contexts = a
                .context_memberships
                .intersection(&b.context_memberships)
                .count();

            #[allow(clippy::cast_precision_loss)]
            let context_penalty =
                (shared_contexts as f64 * shared_context_penalty).min(shared_context_penalty_cap);
            pair_independence -= context_penalty;

            // Penalty for mutual endorsements.
            let a_endorsed_b = a.endorsements.contains(&b.did);
            let b_endorsed_a = b.endorsements.contains(&a.did);

            if a_endorsed_b {
                pair_independence -= mutual_endorsement_penalty;
            }
            if b_endorsed_a {
                pair_independence -= mutual_endorsement_penalty;
            }

            // Clamp to [0.0, 1.0].
            pair_independence = pair_independence.clamp(0.0, 1.0);

            total_pair_score += pair_independence;
            pair_count += 1;
        }
    }

    if pair_count == 0 {
        return 1.0;
    }

    // pair_count is a small integer; precision loss is negligible.
    #[allow(clippy::cast_precision_loss)]
    let score = total_pair_score / pair_count as f64;
    score
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_arguments
)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use scp_clock::TestClock;

    /// A test resolver that maps DIDs to public key bytes.
    struct TestResolver {
        keys: HashMap<String, Vec<u8>>,
    }

    impl TestResolver {
        fn new() -> Self {
            Self {
                keys: HashMap::new(),
            }
        }

        fn add_key(&mut self, did: &str, public_key: Vec<u8>) {
            self.keys.insert(did.to_owned(), public_key);
        }
    }

    impl DidPublicKeyResolver for TestResolver {
        fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
            self.keys
                .get(did)
                .cloned()
                .ok_or_else(|| TrustError::AttestationSignatureInvalid {
                    attestation_id: String::new(),
                    reason: format!("DID not found: {did}"),
                })
        }
    }

    /// Creates a test signing key and returns (`signing_key`, `verifying_key_bytes`).
    fn test_keypair() -> (SigningKey, Vec<u8>) {
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key.to_bytes().to_vec())
    }

    /// Creates and signs a test attestation with `RevocationStatus::Active`.
    fn make_signed_attestation(
        signing_key: &SigningKey,
        attestation_type: AttestationType,
        issuer: &str,
        subject: &str,
        issued_at: u64,
        expires_at: Option<u64>,
        renewal_interval: Option<Duration>,
        evidence: Option<AttestationEvidence>,
    ) -> Attestation {
        make_signed_attestation_with_revocation(
            signing_key,
            attestation_type,
            issuer,
            subject,
            issued_at,
            expires_at,
            renewal_interval,
            evidence,
            RevocationStatus::Active,
        )
    }

    /// Creates and signs a test attestation with the given `RevocationStatus`.
    ///
    /// The signature is computed over the full canonical bytes including
    /// `revocation_status`, matching the V2 canonical construction.
    fn make_signed_attestation_with_revocation(
        signing_key: &SigningKey,
        attestation_type: AttestationType,
        issuer: &str,
        subject: &str,
        issued_at: u64,
        expires_at: Option<u64>,
        renewal_interval: Option<Duration>,
        evidence: Option<AttestationEvidence>,
        revocation_status: RevocationStatus,
    ) -> Attestation {
        let mut attestation = Attestation {
            id: format!("att-{issued_at}"),
            attestation_type,
            issuer: issuer.into(),
            subject: subject.into(),
            claim: serde_json::json!({"test": true}),
            evidence,
            issued_at,
            expires_at,
            renewal_interval,
            renewed_at: None,
            revocation_status,
            signature: vec![],
        };

        let canonical = canonical_attestation_bytes(&attestation).unwrap();
        let sig = signing_key.sign(&canonical);
        attestation.signature = sig.to_bytes().to_vec();
        attestation
    }

    // -----------------------------------------------------------------------
    // verify_attestation tests
    // -----------------------------------------------------------------------

    #[test]
    fn verify_attestation_succeeds_with_valid_signature() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
        );

        let result = verify_attestation(&attestation, &resolver, &clock);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn verify_attestation_rejects_invalid_signature() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let mut attestation = make_signed_attestation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
        );

        // Corrupt the signature.
        attestation.signature[0] ^= 0xff;

        let result = verify_attestation(&attestation, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::AttestationSignatureInvalid { .. }) => {}
            other => panic!("expected AttestationSignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_attestation_rejects_wrong_public_key() {
        let (signing_key, _) = test_keypair();
        let (_, other_pubkey) = test_keypair();
        let mut resolver = TestResolver::new();
        // Register a different key for the issuer DID.
        resolver.add_key("did:key:issuer", other_pubkey);
        let clock = TestClock::new(1000);

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
        );

        let result = verify_attestation(&attestation, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::AttestationSignatureInvalid { .. }) => {}
            other => panic!("expected AttestationSignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_attestation_rejects_expired() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        // Clock is past expiry.
        let clock = TestClock::new(3000);

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
        );

        let result = verify_attestation(&attestation, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::AttestationExpired {
                expired_at: 2000, ..
            }) => {}
            other => panic!("expected AttestationExpired, got {other:?}"),
        }
    }

    #[test]
    fn verify_attestation_rejects_revoked() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        // Sign the attestation with RevocationStatus::Revoked already set.
        // This models an issuer who signs the revocation envelope.
        let attestation = make_signed_attestation_with_revocation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
            RevocationStatus::Revoked {
                revoked_at: 950,
                reason: "compromised".to_owned(),
                revoked_by: "did:key:issuer".into(),
            },
        );

        let result = verify_attestation(&attestation, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::AttestationRevoked {
                revoked_at: 950, ..
            }) => {}
            other => panic!("expected AttestationRevoked, got {other:?}"),
        }
    }

    #[test]
    fn verify_attestation_rejects_tampered_revocation_status() {
        // An attestation signed as Active, then mutated to Revoked by an
        // intermediary, must fail signature verification (not reach the
        // revocation check). This proves revocation_status is in the
        // signed scope.
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let mut attestation = make_signed_attestation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
        );

        // Tamper: flip Active -> Revoked without re-signing.
        attestation.revocation_status = RevocationStatus::Revoked {
            revoked_at: 950,
            reason: "tampered".to_owned(),
            revoked_by: "did:key:issuer".into(),
        };

        let result = verify_attestation(&attestation, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::AttestationSignatureInvalid { .. }) => {}
            other => panic!(
                "expected AttestationSignatureInvalid (tampered revocation_status), got {other:?}"
            ),
        }
    }

    #[test]
    fn verify_attestation_requires_evidence_for_outlet_integrity() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::OutletIntegrity,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None, // No evidence -- should fail.
        );

        let result = verify_attestation(&attestation, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::AttestationEvidenceInvalid { .. }) => {}
            other => panic!("expected AttestationEvidenceInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_attestation_accepts_outlet_integrity_with_evidence() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let evidence = AttestationEvidence {
            evidence_type: "hash".to_owned(),
            data: serde_json::json!({"sha256": "abc123"}),
        };

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::OutletIntegrity,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            Some(evidence),
        );

        let result = verify_attestation(&attestation, &resolver, &clock);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn verify_attestation_rejects_empty_evidence_type() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let evidence = AttestationEvidence {
            evidence_type: String::new(),
            data: serde_json::json!({}),
        };

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            Some(evidence),
        );

        let result = verify_attestation(&attestation, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::AttestationEvidenceInvalid { .. }) => {}
            other => panic!("expected AttestationEvidenceInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_attestation_succeeds_without_expiry() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(999_999_999);

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            None, // No expiry.
            None,
            None,
        );

        let result = verify_attestation(&attestation, &resolver, &clock);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    // -----------------------------------------------------------------------
    // check_attestation_freshness tests
    // -----------------------------------------------------------------------

    #[test]
    fn freshness_returns_fresh_when_within_renewal_interval() {
        let clock = TestClock::new(1000);
        let attestation = Attestation {
            id: "att-1".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({}),
            evidence: None,
            issued_at: 900,
            expires_at: Some(2000),
            renewal_interval: Some(Duration::from_secs(200)),
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: None,
        };

        assert_eq!(
            check_attestation_freshness(&attestation, &clock),
            FreshnessStatus::Fresh
        );
    }

    #[test]
    fn freshness_returns_stale_when_past_renewal_but_not_expired() {
        // issued_at=900, renewal_interval=50s -> renewal_deadline=950
        // now=1000 -> past renewal but expires_at=2000 -> stale
        let clock = TestClock::new(1000);
        let attestation = Attestation {
            id: "att-1".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({}),
            evidence: None,
            issued_at: 900,
            expires_at: Some(2000),
            renewal_interval: Some(Duration::from_secs(50)),
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: None,
        };

        assert_eq!(
            check_attestation_freshness(&attestation, &clock),
            FreshnessStatus::Stale { since: 950 }
        );
    }

    #[test]
    fn freshness_returns_expired_when_past_expires_at() {
        let clock = TestClock::new(3000);
        let attestation = Attestation {
            id: "att-1".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({}),
            evidence: None,
            issued_at: 900,
            expires_at: Some(2000),
            renewal_interval: Some(Duration::from_secs(50)),
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: None,
        };

        assert_eq!(
            check_attestation_freshness(&attestation, &clock),
            FreshnessStatus::Expired
        );
    }

    #[test]
    fn freshness_uses_renewed_at_when_present_and_still_fresh() {
        // issued_at=900, renewed_at=950, renewal_interval=200s
        // -> renewal_deadline = 950 + 200 = 1150
        // now=1000 -> before deadline -> Fresh
        let clock = TestClock::new(1000);
        let attestation = Attestation {
            id: "att-1".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({}),
            evidence: None,
            issued_at: 900,
            expires_at: Some(2000),
            renewal_interval: Some(Duration::from_secs(200)),
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: Some(950),
        };

        assert_eq!(
            check_attestation_freshness(&attestation, &clock),
            FreshnessStatus::Fresh
        );
    }

    #[test]
    fn freshness_uses_renewed_at_for_stale_calculation() {
        // issued_at=900, renewed_at=950, renewal_interval=30s
        // -> renewal_deadline = 950 + 30 = 980
        // now=1000 -> past deadline but not expired -> Stale { since: 980 }
        //
        // Without renewed_at, deadline would be 900 + 30 = 930, also stale.
        // This test verifies the deadline is based on renewed_at (980), not
        // issued_at (930).
        let clock = TestClock::new(1000);
        let attestation = Attestation {
            id: "att-1".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({}),
            evidence: None,
            issued_at: 900,
            expires_at: Some(2000),
            renewal_interval: Some(Duration::from_secs(30)),
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: Some(950),
        };

        assert_eq!(
            check_attestation_freshness(&attestation, &clock),
            FreshnessStatus::Stale { since: 980 }
        );
    }

    #[test]
    fn freshness_renewed_at_makes_stale_attestation_fresh_again() {
        // issued_at=900, renewal_interval=50s
        // Without renewal: deadline = 900 + 50 = 950, now=1000 -> stale
        // With renewed_at=980: deadline = 980 + 50 = 1030, now=1000 -> fresh
        let clock = TestClock::new(1000);
        let attestation = Attestation {
            id: "att-1".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({}),
            evidence: None,
            issued_at: 900,
            expires_at: Some(2000),
            renewal_interval: Some(Duration::from_secs(50)),
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: Some(980),
        };

        // Would be stale without renewed_at, but fresh with it
        assert_eq!(
            check_attestation_freshness(&attestation, &clock),
            FreshnessStatus::Fresh
        );
    }

    #[test]
    fn freshness_returns_fresh_when_no_renewal_interval() {
        let clock = TestClock::new(1500);
        let attestation = Attestation {
            id: "att-1".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({}),
            evidence: None,
            issued_at: 900,
            expires_at: Some(2000),
            renewal_interval: None, // No renewal interval -> always fresh until expired.
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: None,
        };

        assert_eq!(
            check_attestation_freshness(&attestation, &clock),
            FreshnessStatus::Fresh
        );
    }

    #[test]
    fn freshness_returns_fresh_when_no_expiry_and_no_renewal() {
        let clock = TestClock::new(999_999);
        let attestation = Attestation {
            id: "att-1".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({}),
            evidence: None,
            issued_at: 900,
            expires_at: None,
            renewal_interval: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: None,
        };

        assert_eq!(
            check_attestation_freshness(&attestation, &clock),
            FreshnessStatus::Fresh
        );
    }

    // -----------------------------------------------------------------------
    // check_threshold_attestation tests
    // -----------------------------------------------------------------------

    fn make_attestor(
        did: &str,
        contexts: &[&str],
        endorsements: &[&str],
        attestation: Option<Attestation>,
    ) -> AttestorInfo {
        AttestorInfo {
            did: did.into(),
            context_memberships: contexts.iter().map(|s| (*s).to_owned()).collect(),
            endorsements: endorsements.iter().map(|s| DID::from(*s)).collect(),
            attestation,
        }
    }

    fn make_simple_attestation(attestation_type: AttestationType, issuer: &str) -> Attestation {
        Attestation {
            id: format!("att-{issuer}"),
            attestation_type,
            issuer: issuer.into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({}),
            evidence: None,
            issued_at: 1000,
            expires_at: Some(2000),
            renewal_interval: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: None,
        }
    }

    #[test]
    fn threshold_met_with_sufficient_independent_attestors() {
        let att_type = AttestationType::Endorsement;
        let attestors = vec![
            make_attestor(
                "did:key:a",
                &["ctx-1"],
                &[],
                Some(make_simple_attestation(att_type.clone(), "did:key:a")),
            ),
            make_attestor(
                "did:key:b",
                &["ctx-2"],
                &[],
                Some(make_simple_attestation(att_type.clone(), "did:key:b")),
            ),
            make_attestor(
                "did:key:c",
                &["ctx-3"],
                &[],
                Some(make_simple_attestation(att_type.clone(), "did:key:c")),
            ),
        ];

        let requirement = ThresholdRequirement::new(2, 3, 0.5);

        let result = check_threshold_attestation(&att_type, &attestors, &requirement);
        assert!(result.met, "threshold should be met: {result:?}");
        assert_eq!(result.valid_count, 3);
        assert!(
            (result.independence_score - 1.0).abs() < f64::EPSILON,
            "fully independent attestors should have score 1.0, got {}",
            result.independence_score
        );
    }

    #[test]
    fn threshold_not_met_with_insufficient_count() {
        let att_type = AttestationType::Endorsement;
        let attestors = vec![make_attestor(
            "did:key:a",
            &[],
            &[],
            Some(make_simple_attestation(att_type.clone(), "did:key:a")),
        )];

        let requirement = ThresholdRequirement::new(3, 5, 0.5);

        let result = check_threshold_attestation(&att_type, &attestors, &requirement);
        assert!(!result.met, "threshold should NOT be met: {result:?}");
        assert_eq!(result.valid_count, 1);
    }

    #[test]
    fn threshold_not_met_with_low_independence() {
        let att_type = AttestationType::Endorsement;
        // Two attestors that share many contexts and endorse each other.
        let attestors = vec![
            make_attestor(
                "did:key:a",
                &["ctx-1", "ctx-2", "ctx-3", "ctx-4", "ctx-5"],
                &["did:key:b"],
                Some(make_simple_attestation(att_type.clone(), "did:key:a")),
            ),
            make_attestor(
                "did:key:b",
                &["ctx-1", "ctx-2", "ctx-3", "ctx-4", "ctx-5"],
                &["did:key:a"],
                Some(make_simple_attestation(att_type.clone(), "did:key:b")),
            ),
        ];

        let requirement = ThresholdRequirement::new(2, 2, 0.5);

        let result = check_threshold_attestation(&att_type, &attestors, &requirement);
        assert!(
            !result.met,
            "threshold should NOT be met due to low independence: {result:?}"
        );
        assert_eq!(result.valid_count, 2);
        // 5 shared contexts => 0.5 penalty (capped), 2 mutual endorsements => 0.4 penalty
        // independence = 1.0 - 0.5 - 0.4 = 0.1
        assert!(
            (result.independence_score - 0.1).abs() < f64::EPSILON,
            "expected ~0.1 independence, got {}",
            result.independence_score
        );
    }

    #[test]
    fn threshold_ignores_wrong_attestation_type() {
        let required_type = AttestationType::Endorsement;
        let wrong_type = AttestationType::OutletIntegrity;

        let attestors = vec![
            make_attestor(
                "did:key:a",
                &[],
                &[],
                Some(make_simple_attestation(wrong_type, "did:key:a")),
            ),
            make_attestor("did:key:b", &[], &[], None),
        ];

        let requirement = ThresholdRequirement::new(1, 2, 0.5);

        let result = check_threshold_attestation(&required_type, &attestors, &requirement);
        assert!(
            !result.met,
            "threshold should NOT be met (wrong type): {result:?}"
        );
        assert_eq!(result.valid_count, 0);
    }

    #[test]
    fn threshold_single_attestor_has_full_independence() {
        let att_type = AttestationType::Endorsement;
        let attestors = vec![make_attestor(
            "did:key:a",
            &["ctx-1", "ctx-2"],
            &["did:key:b"],
            Some(make_simple_attestation(att_type.clone(), "did:key:a")),
        )];

        let requirement = ThresholdRequirement::new(1, 1, 0.5);

        let result = check_threshold_attestation(&att_type, &attestors, &requirement);
        assert!(
            result.met,
            "single attestor should meet threshold: {result:?}"
        );
        assert!(
            (result.independence_score - 1.0).abs() < f64::EPSILON,
            "single attestor should have 1.0 independence"
        );
    }

    #[test]
    fn independence_reduced_by_shared_contexts() {
        let att_type = AttestationType::Endorsement;
        // Two attestors sharing 3 contexts (0.3 penalty) and no endorsements.
        let attestors = vec![
            make_attestor(
                "did:key:a",
                &["ctx-1", "ctx-2", "ctx-3"],
                &[],
                Some(make_simple_attestation(att_type.clone(), "did:key:a")),
            ),
            make_attestor(
                "did:key:b",
                &["ctx-1", "ctx-2", "ctx-3", "ctx-4"],
                &[],
                Some(make_simple_attestation(att_type.clone(), "did:key:b")),
            ),
        ];

        let requirement = ThresholdRequirement::new(2, 2, 0.5);

        let result = check_threshold_attestation(&att_type, &attestors, &requirement);
        assert!(result.met, "0.7 independence >= 0.5 threshold: {result:?}");
        // 3 shared contexts => 0.3 penalty. Independence = 0.7.
        assert!(
            (result.independence_score - 0.7).abs() < 0.001,
            "expected ~0.7 independence, got {}",
            result.independence_score
        );
    }

    #[test]
    fn independence_reduced_by_mutual_endorsements() {
        let att_type = AttestationType::Endorsement;
        // Two attestors with no shared contexts but mutual endorsements.
        let attestors = vec![
            make_attestor(
                "did:key:a",
                &[],
                &["did:key:b"],
                Some(make_simple_attestation(att_type.clone(), "did:key:a")),
            ),
            make_attestor(
                "did:key:b",
                &[],
                &["did:key:a"],
                Some(make_simple_attestation(att_type.clone(), "did:key:b")),
            ),
        ];

        let requirement = ThresholdRequirement::new(2, 2, 0.5);

        let result = check_threshold_attestation(&att_type, &attestors, &requirement);
        // Mutual endorsements: A->B = -0.2, B->A = -0.2 => independence = 0.6.
        assert!(result.met, "0.6 >= 0.5: {result:?}");
        assert!(
            (result.independence_score - 0.6).abs() < 0.001,
            "expected ~0.6, got {}",
            result.independence_score
        );
    }

    // -------------------------------------------------------------------
    // length prefix prevents field boundary ambiguity
    // -------------------------------------------------------------------

    #[test]
    fn canonical_attestation_boundary_shift_produces_different_bytes() {
        let att_a = Attestation {
            id: "att-AB".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:CD".into(),
            subject: "did:key:subj".into(),
            claim: serde_json::json!({"x": 1}),
            evidence: None,
            issued_at: 1000,
            expires_at: None,
            renewal_interval: None,
            renewed_at: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![],
        };

        let att_b = Attestation {
            id: "att-ABC".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:D".into(),
            subject: "did:key:subj".into(),
            claim: serde_json::json!({"x": 1}),
            evidence: None,
            issued_at: 1000,
            expires_at: None,
            renewal_interval: None,
            renewed_at: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![],
        };

        let bytes_a = canonical_attestation_bytes(&att_a).unwrap();
        let bytes_b = canonical_attestation_bytes(&att_b).unwrap();
        assert_ne!(
            bytes_a, bytes_b,
            "shifting bytes between id and issuer must produce different canonical bytes"
        );
    }

    // -------------------------------------------------------------------
    // §9.5.2 claim serialization scheme: compact JSON (RFC 8785 JCS)
    // -------------------------------------------------------------------

    /// Pins the §9.5.2 Attestation row-5 scheme: the signed preimage embeds
    /// the `claim` as length-prefixed **compact JSON** (no whitespace, sorted
    /// keys per RFC 8785 JCS) — not `MessagePack`.
    #[test]
    fn canonical_attestation_claim_is_length_prefixed_compact_json() {
        use crate::crypto::canonical::{CanonicalField, canonical_hash_bytes};
        use sha2::{Digest, Sha256};

        let make = |claim: serde_json::Value| Attestation {
            id: "att-claim-scheme".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subj".into(),
            claim,
            evidence: None,
            issued_at: 1000,
            expires_at: None,
            renewal_interval: None,
            renewed_at: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![],
        };

        let att = make(serde_json::json!({"z": 2, "a": 1}));
        let canonical = canonical_attestation_bytes(&att).unwrap();

        // Expected claim bytes: compact JSON, keys sorted by Unicode code
        // point (RFC 8785). Equivalent to Python
        // json.dumps(separators=(',', ':')) for pre-sorted keys.
        let claim_json: &[u8] = br#"{"a":1,"z":2}"#;

        // Reconstruct the full §9.5.2 preimage with the compact-JSON claim
        // embedded as a length-prefixed field, and assert the production
        // digest commits to exactly these bytes.
        let revocation_bytes = rmp_serde::to_vec_named(&att.revocation_status).unwrap();
        let preimage = canonical_hash_bytes(
            b"SCP-ATTESTATION-V1:",
            &[
                CanonicalField::VarBytes(att.id.as_bytes()),
                CanonicalField::U16(super::super::attestation_type_tag(&att.attestation_type)),
                CanonicalField::VarBytes(att.issuer.as_bytes()),
                CanonicalField::VarBytes(att.subject.as_bytes()),
                CanonicalField::VarBytes(claim_json),
                CanonicalField::Absent,
                CanonicalField::U64(att.issued_at),
                CanonicalField::Absent,
                CanonicalField::VarBytes(&revocation_bytes),
            ],
        )
        .unwrap();

        // The preimage embeds the length-prefixed compact-JSON claim bytes.
        let mut expected_claim_field = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        expected_claim_field.extend_from_slice(&(claim_json.len() as u32).to_be_bytes());
        expected_claim_field.extend_from_slice(claim_json);
        assert!(
            preimage
                .windows(expected_claim_field.len())
                .any(|window| window == expected_claim_field.as_slice()),
            "preimage must embed the length-prefixed compact-JSON claim {:?}",
            String::from_utf8_lossy(claim_json)
        );

        let expected_digest: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(
            canonical,
            expected_digest.to_vec(),
            "canonical_attestation_bytes must be the SHA-256 of the §9.5.2 \
             preimage with the claim as compact JSON"
        );

        // Key-insertion order must not affect the preimage: JCS sorts object
        // keys, so a semantically identical claim constructed in a different
        // order yields byte-identical canonical bytes.
        let att_reordered = make(serde_json::json!({"a": 1, "z": 2}));
        let canonical_reordered = canonical_attestation_bytes(&att_reordered).unwrap();
        assert_eq!(
            canonical, canonical_reordered,
            "claim key order must not change the canonical bytes (JCS sorts keys)"
        );
    }

    /// Pins the documented RFC 8785 f64 rounding class for claim integers
    /// beyond 2^53 (§9.5.2 I-JSON constraint, RFC 7493).
    ///
    /// RFC 8785 serializes JSON numbers as ES6 IEEE-754 doubles, so distinct
    /// claim integers in the same f64 rounding class canonicalize to
    /// IDENTICAL bytes — a signature over one validly covers the other. This
    /// is inherent to RFC 8785 (not a defect in this implementation, and not
    /// something to "fix" here): it is why §9.5.2 requires claim numeric
    /// values to stay within |n| ≤ 2^53 and large identifiers (snowflake IDs,
    /// u64 counters) to be string-encoded. The test makes the hazard visible
    /// and pins the current behavior; the string-encoded forms of the same
    /// values remain distinct.
    #[test]
    fn canonical_attestation_claim_integers_beyond_2_53_collide_per_rfc8785() {
        let make = |claim: serde_json::Value| Attestation {
            id: "att-claim-numeric".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subj".into(),
            claim,
            evidence: None,
            issued_at: 1000,
            expires_at: None,
            renewal_interval: None,
            renewed_at: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![],
        };

        // 2^53 = 9007199254740992 is exactly representable as an f64;
        // 2^53 + 1 = 9007199254740993 is NOT, and rounds to 2^53 under
        // RFC 8785 / ES6 number serialization.
        let att_exact = make(serde_json::json!({"id": 9_007_199_254_740_992_u64}));
        let att_plus_one = make(serde_json::json!({"id": 9_007_199_254_740_993_u64}));

        let canonical_exact = canonical_attestation_bytes(&att_exact).unwrap();
        let canonical_plus_one = canonical_attestation_bytes(&att_plus_one).unwrap();

        // Documented rounding-class collision: distinct claims differing only
        // beyond f64 precision produce IDENTICAL canonical bytes, so one
        // signature covers both. This is why §9.5.2 mandates string-encoding
        // for identifiers beyond 2^53.
        assert_eq!(
            canonical_exact, canonical_plus_one,
            "claim integers in the same f64 rounding class must canonicalize \
             identically per RFC 8785 (documented §9.5.2 hazard)"
        );

        // The mandated mitigation preserves injectivity: string-encoded forms
        // of the same two values yield distinct canonical bytes.
        let att_exact_str = make(serde_json::json!({"id": "9007199254740992"}));
        let att_plus_one_str = make(serde_json::json!({"id": "9007199254740993"}));
        assert_ne!(
            canonical_attestation_bytes(&att_exact_str).unwrap(),
            canonical_attestation_bytes(&att_plus_one_str).unwrap(),
            "string-encoded identifiers must remain distinct in the preimage"
        );
    }

    // -----------------------------------------------------------------------
    // IdentityDidPublicKeyResolver tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolver_did_key_hex_valid() {
        let resolver = IdentityDidPublicKeyResolver;
        let key_hex = "a".repeat(64); // 32 bytes
        let did = format!("did:key:{key_hex}");
        let result = resolver.resolve_public_key(&did);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn resolver_did_key_invalid_hex() {
        let resolver = IdentityDidPublicKeyResolver;
        let result = resolver.resolve_public_key("did:key:not-valid-hex!");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("did:key"),
            "error should mention did:key: {err}"
        );
    }

    #[test]
    fn resolver_unsupported_method() {
        let resolver = IdentityDidPublicKeyResolver;
        let result = resolver.resolve_public_key("did:web:example.com");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("unsupported"),
            "error should mention unsupported: {err}"
        );
    }

    #[test]
    fn resolver_empty_string() {
        let resolver = IdentityDidPublicKeyResolver;
        let result = resolver.resolve_public_key("");
        assert!(result.is_err());
    }

    #[test]
    fn resolver_did_dht_malformed() {
        let resolver = IdentityDidPublicKeyResolver;
        // Valid prefix but garbage z-base-32
        let result = resolver.resolve_public_key("did:dht:z!@#$%^&*");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // revocation_status in signed scope tests
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_bytes_differ_for_active_vs_revoked() {
        let active = Attestation {
            id: "att-1".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({"test": true}),
            evidence: None,
            issued_at: 1000,
            expires_at: Some(2000),
            renewal_interval: None,
            renewed_at: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![],
        };

        let revoked = Attestation {
            revocation_status: RevocationStatus::Revoked {
                revoked_at: 1500,
                reason: "compromised".to_owned(),
                revoked_by: "did:key:issuer".into(),
            },
            ..active.clone()
        };

        let bytes_active = canonical_attestation_bytes(&active).unwrap();
        let bytes_revoked = canonical_attestation_bytes(&revoked).unwrap();
        assert_ne!(
            bytes_active, bytes_revoked,
            "revocation_status must be in the signed scope: Active and Revoked \
             must produce different canonical bytes"
        );
    }

    #[test]
    fn renewal_fields_are_unauthenticated_outside_signed_scope() {
        // Pins the documented ADVISORY/UNAUTHENTICATED contract (#1999): the
        // `renewal_interval` / `renewed_at` fields are NOT in the signed
        // attestation preimage, so mutating them changes neither the canonical
        // bytes nor the validity of the issuer signature. A verifier therefore
        // cannot detect (and MUST NOT trust) a holder/relay bumping them.
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        // Sign with no renewal metadata.
        let signed = make_signed_attestation_with_revocation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None, // renewal_interval
            None, // evidence
            RevocationStatus::Active,
        );
        assert!(signed.renewal_interval.is_none());
        assert!(signed.renewed_at.is_none());

        let baseline_bytes = canonical_attestation_bytes(&signed).unwrap();
        assert!(
            verify_attestation(&signed, &resolver, &clock).is_ok(),
            "baseline attestation must verify"
        );

        // Adversarially mutate BOTH renewal fields (as a holder/relay would to
        // fake freshness), keeping the original signature untouched.
        let mut tampered = signed;
        tampered.renewal_interval = Some(Duration::from_hours(8760));
        tampered.renewed_at = Some(999_999);

        // 1. Canonical bytes are byte-identical — the fields are outside the
        //    authenticated set.
        let tampered_bytes = canonical_attestation_bytes(&tampered).unwrap();
        assert_eq!(
            baseline_bytes, tampered_bytes,
            "renewal_interval/renewed_at must NOT affect canonical_attestation_bytes"
        );

        // 2. The original signature still verifies over the tampered struct —
        //    proving the mutation is undetectable via the signature.
        assert!(
            verify_attestation(&tampered, &resolver, &clock).is_ok(),
            "mutating unauthenticated renewal fields must not invalidate the signature"
        );
    }

    #[test]
    fn identity_resolver_is_total_for_accepted_did_forms() {
        // #2000: the aggregate read path (`trust::aggregate`) drops any cached
        // attestation whose re-verification Errs, which is sound ONLY if the
        // injected resolver is TOTAL — every Err is terminal (key cannot exist
        // / malformed DID), never a transient/infra fault. The production
        // `IdentityDidPublicKeyResolver` is a pure DID-string parse with no I/O,
        // so it is total by construction. This test pins that:
        //   (a) every well-formed accepted DID form resolves `Ok`, and
        //   (b) malformed / unsupported inputs `Err` terminally AND
        //       deterministically (same input always yields the same outcome),
        //       which is the observable proxy for "no transient error path".
        use scp_did::did_dht_from_public_key;

        let resolver = IdentityDidPublicKeyResolver;
        let key = [7u8; 32];

        // (a) Accepted forms → Ok, round-tripping to the embedded key.
        let did_dht = did_dht_from_public_key(&key);
        assert_eq!(
            resolver.resolve_public_key(did_dht.as_ref()).unwrap(),
            key.to_vec(),
            "valid did:dht:z must resolve to its embedded key",
        );
        let did_key = format!("did:key:{}", hex::encode(key));
        assert_eq!(
            resolver.resolve_public_key(&did_key).unwrap(),
            key.to_vec(),
            "valid did:key:{{hex}} (testing form) must resolve",
        );

        // (b) Malformed / unsupported inputs → terminal, deterministic Err.
        // A total, pure resolver never returns Err for a resolvable key and
        // never flips Ok↔Err for the same input across calls (which a
        // networked/cache resolver could). Determinism here stands in for
        // "no transient failure".
        let terminal_cases = [
            "",                    // empty
            "not-a-did",           // no scheme
            "did:web:example.com", // unsupported method
            "did:dht:z!@#$%^&*",   // invalid z-base-32
            "did:dht:zyyy",        // decodes but wrong length
            "did:key:zzzz",        // invalid hex
            "did:key:00",          // hex but wrong length
        ];
        for input in terminal_cases {
            let first = resolver.resolve_public_key(input);
            let second = resolver.resolve_public_key(input);
            assert!(first.is_err(), "expected terminal Err for {input:?}");
            assert_eq!(
                first.is_ok(),
                second.is_ok(),
                "resolver must be deterministic (no transient behavior) for {input:?}",
            );
        }
    }

    // --- ThresholdRequirement NaN / Infinity guard tests ---

    #[test]
    fn threshold_requirement_validate_rejects_nan_independence() {
        let t = ThresholdRequirement::new(2, 3, f64::NAN);
        let err = t.validate().unwrap_err();
        assert!(
            err.contains("independence_threshold"),
            "error should name the field: {err}"
        );
    }

    #[test]
    fn threshold_requirement_validate_rejects_infinity() {
        let t = ThresholdRequirement::new_with_penalties(2, 3, 0.5, f64::INFINITY, 0.5, 0.2);
        let err = t.validate().unwrap_err();
        assert!(
            err.contains("shared_context_penalty"),
            "error should name the field: {err}"
        );
    }

    #[test]
    fn threshold_requirement_validate_rejects_neg_infinity() {
        let t = ThresholdRequirement::new_with_penalties(2, 3, 0.5, 0.1, 0.5, f64::NEG_INFINITY);
        let err = t.validate().unwrap_err();
        assert!(
            err.contains("mutual_endorsement_penalty"),
            "error should name the field: {err}"
        );
    }

    #[test]
    fn threshold_requirement_validate_accepts_finite_values() {
        let t = ThresholdRequirement::new(2, 3, 0.5);
        assert!(t.validate().is_ok());
    }

    #[test]
    fn threshold_requirement_serde_roundtrip_finite() {
        let t = ThresholdRequirement::new(2, 3, 0.5);
        let json = serde_json::to_string(&t).unwrap();
        let back: ThresholdRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn threshold_requirement_serde_backward_compat_defaults() {
        // Deserialize without optional penalty fields — should use defaults.
        let json = r#"{"required_count":2,"total_attestors":3,"independence_threshold":0.5}"#;
        let t: ThresholdRequirement = serde_json::from_str(json).unwrap();
        assert_eq!(t.required_count(), 2);
        assert_eq!(t.total_attestors(), 3);
        assert!((t.independence_threshold() - 0.5).abs() < f64::EPSILON);
        assert!((t.shared_context_penalty() - 0.1).abs() < f64::EPSILON);
        assert!((t.shared_context_penalty_cap() - 0.5).abs() < f64::EPSILON);
        assert!((t.mutual_endorsement_penalty() - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn threshold_requirement_serde_accepts_unknown_fields() {
        // Wire-format types must tolerate unknown fields for forward
        // compatibility — a newer sender may include fields this version
        // doesn't know about yet.
        let json = r#"{"required_count":2,"total_attestors":3,"independence_threshold":0.5,"evil_field":true}"#;
        let result: Result<ThresholdRequirement, _> = serde_json::from_str(json);
        assert!(
            result.is_ok(),
            "unknown fields must be accepted for forward compatibility: {result:?}"
        );
    }

    // --- Value range validation tests ---

    #[test]
    fn threshold_requirement_rejects_independence_below_zero() {
        let t = ThresholdRequirement::new(2, 3, -0.1);
        let err = t.validate().unwrap_err();
        assert!(
            err.contains("independence_threshold"),
            "error should mention independence_threshold: {err}"
        );
    }

    #[test]
    fn threshold_requirement_rejects_independence_above_one() {
        let t = ThresholdRequirement::new(2, 3, 1.01);
        let err = t.validate().unwrap_err();
        assert!(
            err.contains("independence_threshold"),
            "error should mention independence_threshold: {err}"
        );
    }

    #[test]
    fn threshold_requirement_accepts_independence_boundary_values() {
        // 0.0 and 1.0 are both valid boundary values.
        assert!(ThresholdRequirement::new(2, 3, 0.0).validate().is_ok());
        assert!(ThresholdRequirement::new(2, 3, 1.0).validate().is_ok());
    }

    #[test]
    fn threshold_requirement_rejects_negative_shared_context_penalty() {
        let t = ThresholdRequirement::new_with_penalties(2, 3, 0.5, -0.01, 0.5, 0.2);
        let err = t.validate().unwrap_err();
        assert!(
            err.contains("shared_context_penalty"),
            "error should mention shared_context_penalty: {err}"
        );
    }

    #[test]
    fn threshold_requirement_rejects_negative_shared_context_penalty_cap() {
        let t = ThresholdRequirement::new_with_penalties(2, 3, 0.5, 0.1, -0.01, 0.2);
        let err = t.validate().unwrap_err();
        assert!(
            err.contains("shared_context_penalty_cap"),
            "error should mention shared_context_penalty_cap: {err}"
        );
    }

    #[test]
    fn threshold_requirement_rejects_negative_mutual_endorsement_penalty() {
        let t = ThresholdRequirement::new_with_penalties(2, 3, 0.5, 0.1, 0.5, -0.01);
        let err = t.validate().unwrap_err();
        assert!(
            err.contains("mutual_endorsement_penalty"),
            "error should mention mutual_endorsement_penalty: {err}"
        );
    }

    #[test]
    fn threshold_requirement_rejects_required_count_exceeding_total() {
        let t = ThresholdRequirement::new(5, 3, 0.5);
        let err = t.validate().unwrap_err();
        assert!(
            err.contains("required_count"),
            "error should mention required_count: {err}"
        );
    }

    #[test]
    fn threshold_requirement_accepts_required_count_equal_to_total() {
        let t = ThresholdRequirement::new(3, 3, 0.5);
        assert!(t.validate().is_ok());
    }

    #[test]
    fn threshold_requirement_try_new_enforces_ranges() {
        assert!(ThresholdRequirement::try_new(5, 3, 0.5).is_err());
        assert!(ThresholdRequirement::try_new(2, 3, -0.1).is_err());
        assert!(ThresholdRequirement::try_new(2, 3, 1.5).is_err());
        assert!(ThresholdRequirement::try_new(2, 3, 0.5).is_ok());
    }

    #[test]
    fn threshold_requirement_try_new_with_penalties_enforces_ranges() {
        // Negative penalty.
        assert!(ThresholdRequirement::try_new_with_penalties(2, 3, 0.5, -0.1, 0.5, 0.2).is_err());
        // required_count > total_attestors.
        assert!(ThresholdRequirement::try_new_with_penalties(5, 3, 0.5, 0.1, 0.5, 0.2).is_err());
        // Valid.
        assert!(ThresholdRequirement::try_new_with_penalties(2, 3, 0.5, 0.1, 0.5, 0.2).is_ok());
    }

    #[test]
    fn threshold_requirement_serde_rejects_invalid_ranges() {
        // independence_threshold > 1.0.
        let json = r#"{"required_count":2,"total_attestors":3,"independence_threshold":1.5}"#;
        assert!(serde_json::from_str::<ThresholdRequirement>(json).is_err());

        // required_count > total_attestors.
        let json = r#"{"required_count":5,"total_attestors":3,"independence_threshold":0.5}"#;
        assert!(serde_json::from_str::<ThresholdRequirement>(json).is_err());

        // Negative penalty.
        let json = r#"{"required_count":2,"total_attestors":3,"independence_threshold":0.5,"shared_context_penalty":-0.1}"#;
        assert!(serde_json::from_str::<ThresholdRequirement>(json).is_err());
    }

    // --- Accessor method tests ---

    #[test]
    fn threshold_requirement_accessor_methods() {
        let t = ThresholdRequirement::new_with_penalties(2, 5, 0.7, 0.15, 0.6, 0.25);
        assert_eq!(t.required_count(), 2);
        assert_eq!(t.total_attestors(), 5);
        assert!((t.independence_threshold() - 0.7).abs() < f64::EPSILON);
        assert!((t.shared_context_penalty() - 0.15).abs() < f64::EPSILON);
        assert!((t.shared_context_penalty_cap() - 0.6).abs() < f64::EPSILON);
        assert!((t.mutual_endorsement_penalty() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn verify_attestation_rejects_revoked_by_non_issuer() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        // Sign the attestation with revoked_by pointing to a non-issuer DID.
        // The issuer signs this envelope (so the signature is valid), but the
        // revoked_by field doesn't match the issuer -- this must be rejected.
        let attestation = make_signed_attestation_with_revocation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
            RevocationStatus::Revoked {
                revoked_at: 950,
                reason: "unauthorized".to_owned(),
                revoked_by: "did:key:attacker".into(),
            },
        );

        let result = verify_attestation(&attestation, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::AttestationRevocationInvalid {
                revoked_by, issuer, ..
            }) => {
                assert_eq!(revoked_by, "did:key:attacker");
                assert_eq!(issuer, "did:key:issuer");
            }
            other => panic!("expected AttestationRevocationInvalid, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // AttestationRevocationChecker tests
    // -----------------------------------------------------------------------

    #[test]
    fn noop_revocation_checker_returns_none() {
        let checker = NoOpRevocationChecker;
        let result = checker.check_revocation("att-1", &DID::from("did:key:issuer"));
        assert!(result.is_none());
    }

    /// A test revocation checker that always reports a specific attestation as
    /// revoked at a given timestamp.
    struct AlwaysRevokedChecker {
        revoked_at: u64,
    }

    impl AttestationRevocationChecker for AlwaysRevokedChecker {
        fn check_revocation(&self, _attestation_id: &str, _issuer: &DID) -> Option<u64> {
            Some(self.revoked_at)
        }
    }

    /// A test revocation checker that only revokes a specific attestation ID.
    struct SelectiveRevokedChecker {
        target_id: String,
        revoked_at: u64,
    }

    impl AttestationRevocationChecker for SelectiveRevokedChecker {
        fn check_revocation(&self, attestation_id: &str, _issuer: &DID) -> Option<u64> {
            if attestation_id == self.target_id {
                Some(self.revoked_at)
            } else {
                None
            }
        }
    }

    #[test]
    fn verify_attestation_with_revocation_checker_rejects_revoked() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
        );

        let checker = AlwaysRevokedChecker { revoked_at: 999 };
        let result =
            verify_attestation_with_revocation(&attestation, &resolver, &clock, Some(&checker));
        assert!(result.is_err());
        match result {
            Err(TrustError::AttestationRevoked {
                revoked_at: 999, ..
            }) => {}
            other => panic!("expected AttestationRevoked, got {other:?}"),
        }
    }

    #[test]
    fn verify_attestation_with_noop_checker_succeeds() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
        );

        let checker = NoOpRevocationChecker;
        let result =
            verify_attestation_with_revocation(&attestation, &resolver, &clock, Some(&checker));
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn verify_attestation_with_none_checker_succeeds() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
        );

        let result = verify_attestation_with_revocation(&attestation, &resolver, &clock, None);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn verify_attestation_field_revocation_takes_precedence_over_checker() {
        // Even with a noop checker, a revoked field should fail.
        // Must use make_signed_attestation_with_revocation so the signature
        // covers the revocation_status (it's in the signed scope).
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let attestation = make_signed_attestation_with_revocation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
            RevocationStatus::Revoked {
                revoked_at: 950,
                reason: "compromised".to_owned(),
                revoked_by: "did:key:issuer".into(),
            },
        );

        let checker = NoOpRevocationChecker;
        let result =
            verify_attestation_with_revocation(&attestation, &resolver, &clock, Some(&checker));
        assert!(result.is_err());
        match result {
            Err(TrustError::AttestationRevoked {
                revoked_at: 950, ..
            }) => {}
            other => panic!("expected AttestationRevoked at 950, got {other:?}"),
        }
    }

    #[test]
    fn selective_revocation_checker_only_revokes_targeted_attestation() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::Endorsement,
            "did:key:issuer",
            "did:key:subject",
            900,
            Some(2000),
            None,
            None,
        );

        // Checker targets a different attestation ID.
        let checker = SelectiveRevokedChecker {
            target_id: "some-other-att-id".to_owned(),
            revoked_at: 999,
        };
        let result =
            verify_attestation_with_revocation(&attestation, &resolver, &clock, Some(&checker));
        assert!(
            result.is_ok(),
            "expected Ok for non-targeted attestation, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // AttestationVerificationCache tests
    // -----------------------------------------------------------------------

    #[test]
    fn cache_new_is_empty() {
        let cache = AttestationVerificationCache::new();
        assert!(cache.get("att-1", 1000).is_none());
    }

    #[test]
    fn cache_insert_and_get_success() {
        let mut cache = AttestationVerificationCache::new();
        cache.insert(
            "att-1".to_owned(),
            AttestationClass::Cryptographic,
            Ok(()),
            1000,
        );

        let result = cache.get("att-1", 1000);
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn cache_insert_and_get_error() {
        let mut cache = AttestationVerificationCache::new();
        let err = TrustError::AttestationExpired {
            attestation_id: "att-1".to_owned(),
            expired_at: 900,
        };
        cache.insert(
            "att-1".to_owned(),
            AttestationClass::Reference,
            Err(err),
            1000,
        );

        let result = cache.get("att-1", 1000);
        assert!(result.is_some());
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn cache_reference_ttl_1_hour() {
        let mut cache = AttestationVerificationCache::new();
        cache.insert(
            "att-ref".to_owned(),
            AttestationClass::Reference,
            Ok(()),
            1000,
        );

        // Just within TTL (1000 + 3600 = 4600)
        assert!(cache.get("att-ref", 4600).is_some());

        // Past TTL
        assert!(cache.get("att-ref", 4601).is_none());
    }

    #[test]
    fn cache_cryptographic_ttl_24_hours() {
        let mut cache = AttestationVerificationCache::new();
        cache.insert(
            "att-crypto".to_owned(),
            AttestationClass::Cryptographic,
            Ok(()),
            1000,
        );

        // Just within TTL (1000 + 86400 = 87400)
        assert!(cache.get("att-crypto", 87400).is_some());

        // Past TTL
        assert!(cache.get("att-crypto", 87401).is_none());
    }

    #[test]
    fn cache_evict_expired_removes_stale_entries() {
        let mut cache = AttestationVerificationCache::new();
        cache.insert(
            "att-ref".to_owned(),
            AttestationClass::Reference,
            Ok(()),
            1000,
        );
        cache.insert(
            "att-crypto".to_owned(),
            AttestationClass::Cryptographic,
            Ok(()),
            1000,
        );

        // At 4601: Reference (TTL 3600) is expired, Cryptographic (TTL 86400) is not.
        cache.evict_expired(4601);

        assert!(
            cache.get("att-ref", 1000).is_none(),
            "expired reference should be evicted"
        );
        assert!(
            cache.get("att-crypto", 1000).is_some(),
            "non-expired cryptographic should remain"
        );
    }

    #[test]
    fn cache_overwrite_existing_entry() {
        let mut cache = AttestationVerificationCache::new();
        cache.insert(
            "att-1".to_owned(),
            AttestationClass::Reference,
            Ok(()),
            1000,
        );

        // Overwrite with an error result and different class.
        let err = TrustError::AttestationRevoked {
            attestation_id: "att-1".to_owned(),
            revoked_at: 1500,
        };
        cache.insert(
            "att-1".to_owned(),
            AttestationClass::Cryptographic,
            Err(err),
            2000,
        );

        let result = cache.get("att-1", 2000);
        assert!(result.is_some());
        assert!(result.unwrap().is_err());

        // New entry uses Cryptographic TTL (24h from 2000 = 88400)
        assert!(cache.get("att-1", 88400).is_some());
        assert!(cache.get("att-1", 88401).is_none());
    }

    #[test]
    fn cache_default_trait() {
        let cache = AttestationVerificationCache::default();
        assert!(cache.get("anything", 0).is_none());
    }

    #[test]
    fn cache_ttl_constants_match_spec() {
        assert_eq!(REFERENCE_TTL_SECS, 3600, "Reference TTL should be 1 hour");
        assert_eq!(
            CRYPTOGRAPHIC_TTL_SECS, 86400,
            "Cryptographic TTL should be 24 hours"
        );
    }
}
