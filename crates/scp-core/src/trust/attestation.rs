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

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto::ed25519::verify_ed25519_signature;
use scp_event_log::Ed25519Signature;
use scp_identity::DID;
use scp_identity::cache::Clock;

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
    pub claim: serde_json::Value,
    /// Optional evidence supporting the attestation.
    pub evidence: Option<AttestationEvidence>,
    /// Unix timestamp (seconds) when the attestation was issued.
    pub issued_at: u64,
    /// Optional expiry timestamp (seconds).
    pub expires_at: Option<u64>,
    /// Optional renewal interval. Attestations past this interval but not
    /// expired are considered stale (degraded, not revoked).
    pub renewal_interval: Option<Duration>,
    /// Timestamp (seconds) of the last renewal, if renewable (spec 7.4.1).
    ///
    /// When present, freshness is measured from `renewed_at` instead of
    /// `issued_at`. A renewable attestation that has never been renewed
    /// should set this to `None`, causing freshness to be measured from
    /// `issued_at`.
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
/// a `ToolIntegrity` attestation might include a hash of the tool binary,
/// while an `IdentityLink` attestation might include a signed challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// The type of evidence (e.g., "hash", "signed-challenge", "log-reference").
    pub evidence_type: String,
    /// Evidence data. Interpretation depends on `evidence_type`.
    pub data: serde_json::Value,
}

// ---------------------------------------------------------------------------
// RevocationStatus
// ---------------------------------------------------------------------------

/// Revocation status of an attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationStatus {
    /// The attestation is active and not revoked.
    Active,
    /// The attestation has been revoked.
    Revoked {
        /// Unix timestamp (seconds) when the revocation occurred.
        revoked_at: u64,
        /// Optional reason for revocation.
        reason: Option<String>,
    },
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
/// See ADR-017 acceptance criterion 7.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdRequirement {
    /// The minimum number of valid attestations required (N).
    pub required_count: u32,
    /// The total number of attestors in the set (M).
    pub total_attestors: u32,
    /// Minimum independence score (0.0 to 1.0). Attestors with shared context
    /// memberships or mutual endorsements have reduced independence.
    pub independence_threshold: f64,
    /// Independence penalty per shared context membership between a pair of
    /// attestors. Default: 0.1. Capped at `shared_context_penalty_cap` total.
    #[serde(default = "default_shared_context_penalty")]
    pub shared_context_penalty: f64,
    /// Maximum total penalty from shared context memberships for a single
    /// pair. Default: 0.5.
    #[serde(default = "default_shared_context_penalty_cap")]
    pub shared_context_penalty_cap: f64,
    /// Independence penalty per mutual endorsement direction (A endorsed B
    /// = one direction, B endorsed A = another). Default: 0.2.
    #[serde(default = "default_mutual_endorsement_penalty")]
    pub mutual_endorsement_penalty: f64,
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
#[derive(Debug, Clone)]
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
pub trait DidPublicKeyResolver {
    /// Resolves a DID string to its Ed25519 public key bytes (32 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the DID cannot be resolved.
    fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError>;
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
/// 4. **Revocation:** Rejects if the attestation has been revoked.
///
/// # Errors
///
/// Returns a specific [`TrustError`] variant for each failure mode:
/// - [`TrustError::AttestationSignatureInvalid`] for signature failures
/// - [`TrustError::AttestationExpired`] when past expiry
/// - [`TrustError::AttestationRevoked`] when revoked
/// - [`TrustError::AttestationEvidenceInvalid`] when required evidence is
///   missing or invalid
///
/// See ADR-017 acceptance criteria 3-7.
pub fn verify_attestation(
    attestation: &Attestation,
    resolver: &impl DidPublicKeyResolver,
    clock: &impl Clock,
) -> Result<(), TrustError> {
    // 1. Verify Ed25519 signature against issuer's public key.
    let public_key_bytes = resolver.resolve_public_key(&attestation.issuer)?;
    let canonical = canonical_attestation_bytes(attestation);
    verify_ed25519_signature(&public_key_bytes, &canonical, &attestation.signature).map_err(
        |reason| TrustError::AttestationSignatureInvalid {
            attestation_id: attestation.id.clone(),
            reason,
        },
    )?;

    // 2. Validate evidence per attestation type.
    validate_evidence(attestation)?;

    // 3. Check expiry.
    let now = clock.now();
    if let Some(expires_at) = attestation.expires_at
        && expires_at < now
    {
        return Err(TrustError::AttestationExpired {
            attestation_id: attestation.id.clone(),
            expired_at: expires_at,
        });
    }

    // 4. Check revocation status.
    if let RevocationStatus::Revoked { revoked_at, .. } = &attestation.revocation_status {
        return Err(TrustError::AttestationRevoked {
            attestation_id: attestation.id.clone(),
            revoked_at: *revoked_at,
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
    let now = clock.now();

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
        requirement.shared_context_penalty,
        requirement.shared_context_penalty_cap,
        requirement.mutual_endorsement_penalty,
    );

    let count_met = valid_count >= requirement.required_count;
    let independence_met = independence_score >= requirement.independence_threshold;

    ThresholdResult {
        met: count_met && independence_met,
        valid_count,
        required_count: requirement.required_count,
        independence_score,
        independence_threshold: requirement.independence_threshold,
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
///     || len(claim_json) || claim_json || issued_at_BE
/// ```
///
/// Variable-length fields are prefixed with their length as a 4-byte
/// big-endian u32 to prevent field-boundary ambiguity. The domain separator
/// prevents cross-protocol hash confusion. `attestation_type` uses a stable
/// numeric tag (u16 big-endian) instead of Debug formatting for
/// cross-version determinism. `issued_at` uses big-endian encoding,
/// consistent with all other canonical hash functions.
pub(crate) fn canonical_attestation_bytes(attestation: &Attestation) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SCP-ATTESTATION-V1:");

    // Length-prefix helper for variable-length fields.
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |bytes: &mut Vec<u8>, data: &[u8]| {
        bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(data);
    };

    length_prefix(&mut bytes, attestation.id.as_bytes());
    bytes.extend_from_slice(
        &super::attestation_type_tag(&attestation.attestation_type).to_be_bytes(),
    ); // fixed-width u16, no length prefix needed
    length_prefix(&mut bytes, attestation.issuer.as_bytes());
    length_prefix(&mut bytes, attestation.subject.as_bytes());
    length_prefix(&mut bytes, attestation.claim.to_string().as_bytes());
    bytes.extend_from_slice(&attestation.issued_at.to_be_bytes()); // fixed-width, no prefix needed
    bytes
}

/// Validates that evidence is present and appropriate for the attestation type.
///
/// Some attestation types require evidence:
/// - `ToolIntegrity` requires evidence (hash of the tool).
/// - `ParticipationWitness` requires evidence (log reference).
///
/// Other types accept optional evidence without strict requirements.
fn validate_evidence(attestation: &Attestation) -> Result<(), TrustError> {
    let requires_evidence = matches!(
        attestation.attestation_type,
        AttestationType::ToolIntegrity | AttestationType::ParticipationWitness
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
    use scp_identity::cache::TestClock;

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

    /// Creates and signs a test attestation.
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
            revocation_status: RevocationStatus::Active,
            signature: vec![],
        };

        let canonical = canonical_attestation_bytes(&attestation);
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

        attestation.revocation_status = RevocationStatus::Revoked {
            revoked_at: 950,
            reason: Some("compromised".to_owned()),
        };

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
    fn verify_attestation_requires_evidence_for_tool_integrity() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(1000);

        let attestation = make_signed_attestation(
            &signing_key,
            AttestationType::ToolIntegrity,
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
    fn verify_attestation_accepts_tool_integrity_with_evidence() {
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
            AttestationType::ToolIntegrity,
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
        let wrong_type = AttestationType::ToolIntegrity;

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

        let bytes_a = canonical_attestation_bytes(&att_a);
        let bytes_b = canonical_attestation_bytes(&att_b);
        assert_ne!(
            bytes_a, bytes_b,
            "shifting bytes between id and issuer must produce different canonical bytes"
        );
    }
}
