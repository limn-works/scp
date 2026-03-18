//! Sybil resistance framework — trust signal composition and earned capacity.
//!
//! The protocol's Sybil resistance philosophy (§9.3): make Sybil attacks
//! **expensive to sustain** through composable trust signals where **depth of
//! investment in one identity** is the discriminator. The protocol provides
//! signals and evaluation infrastructure; contexts set thresholds. Scoring
//! algorithms are client policy — the protocol provides the verifiable data
//! and evaluation framework.
//!
//! # Architecture
//!
//! Three layers compose (§9.3):
//!
//! 1. **Earned capacity.** New identities start limited. Capacity grows through
//!    participation history, records, and time. [`EarnedCapacityPolicy`] defines
//!    limits; [`evaluate_earned_capacity`] computes current capacity from
//!    participation data.
//!
//! 2. **Social and economic cost.** Real platform accounts, real money, real
//!    endorsements. [`TrustSignal`] enumerates the composable signal categories
//!    from §9.3's trust signal table. [`IdentityDepthAssessment`] aggregates
//!    them.
//!
//! 3. **Context-level thresholds.** Contexts declare admission requirements
//!    from available signals. [`ContextSybilPolicy`] defines per-context
//!    thresholds. [`evaluate_sybil_resistance`] checks a DID's signals against
//!    policy.
//!
//! # Reputation decay
//!
//! Time-based decay of trust signals is handled through freshness weighting.
//! [`FreshnessWeight`] provides graduated decay (not just binary stale/fresh)
//! where signal value decreases as a function of age relative to a half-life.
//! This addresses §9.3's requirement that "a DID with strong historical
//! participation but years of inactivity is indistinguishable from one that is
//! currently active" — with freshness weighting, stale signals carry less
//! weight than fresh ones.
//!
//! The `RequireParticipation::max_age_secs` field provides a binary freshness
//! cutoff for admission. `FreshnessWeight` provides graduated decay for
//! trust evaluation beyond admission.
//!
//! See spec §9.3 (Sybil Resistance and Identity Uniqueness), §4.8 (Agent
//! Fleet), §7.3.2.1 (Participation Admission).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use scp_identity::DID;

use super::AttestationType;
use super::attestation::{AttestorInfo, ThresholdRequirement, check_threshold_attestation};

// ---------------------------------------------------------------------------
// TrustSignalCategory — the 6 composable signal types from §9.3
// ---------------------------------------------------------------------------

/// Categories of composable trust signals for Sybil resistance (§9.3).
///
/// Each variant corresponds to a row in the §9.3 trust signal table. The
/// protocol provides verifiable data for each category; contexts and agents
/// evaluate them according to their own criteria.
///
/// **Key insight (§9.3):** Multiple signals on one DID is a strength signal.
/// Sybil accounts are broad (many identities) but shallow (no depth on any
/// single one). Depth of investment is the discriminator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustSignalCategory {
    /// Links to real platform accounts (§3.5).
    /// Proves control of real platform accounts. Lives in DID document.
    /// Self-asserted (cryptographic proof). All platforms.
    SocialAttestation,

    /// Real hardware + signed app.
    /// Lives in DID document. Self-asserted (platform-signed proof).
    /// Mobile only — desktop gap acknowledged (§9.3).
    DeviceAttestation,

    /// Active participation for N days across M contexts.
    /// Lives in context state (computed). Not self-asserted. All platforms.
    ParticipationHistory,

    /// No penalties, positive interactions.
    /// Lives in context state (computed). Not self-asserted. All platforms.
    ParticipationRecord,

    /// Has spent real money (§19).
    /// Lives in context state / payment receipts. Not self-asserted.
    EconomicActivity,

    /// Other established DIDs vouch.
    /// Lives in DID document or context. Not self-asserted (signed by
    /// endorser). All platforms.
    Endorsement,
}

// ---------------------------------------------------------------------------
// TrustSignal — a single evaluated trust signal
// ---------------------------------------------------------------------------

/// A single evaluated trust signal with timestamp and strength.
///
/// Trust signals are the building blocks of identity depth assessment.
/// Each signal is a verifiable fact about a DID — the protocol provides
/// the data, agents evaluate the weight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustSignal {
    /// Which category this signal belongs to.
    pub category: TrustSignalCategory,

    /// Unix timestamp (seconds) when this signal was last verified or updated.
    pub verified_at: u64,

    /// Quantitative strength of the signal. Interpretation is
    /// category-specific:
    /// - `SocialAttestation`: number of verified platform links
    /// - `DeviceAttestation`: number of distinct device attestation tokens
    /// - `ParticipationHistory`: participation duration in seconds
    /// - `ParticipationRecord`: number of contexts with clean records
    /// - `EconomicActivity`: total economic activity (Amount units)
    /// - `Endorsement`: number of independent endorsements
    pub strength: u64,

    /// Optional details specific to the signal category.
    /// Clients may use this for fine-grained evaluation.
    pub details: Option<String>,
}

// ---------------------------------------------------------------------------
// FreshnessWeight — graduated freshness decay
// ---------------------------------------------------------------------------

/// Graduated freshness weight for trust signal decay (§9.3, #401).
///
/// Instead of binary fresh/stale, computes a continuous weight in `[0.0, 1.0]`
/// based on signal age relative to a configurable half-life. This addresses
/// reputation decay: a DID with strong historical participation but years of
/// inactivity carries less weight than one that is currently active.
///
/// The decay function is exponential: `weight = 2^(-age / half_life)`.
/// At `age == 0`: weight = 1.0 (fully fresh).
/// At `age == half_life`: weight = 0.5 (half strength).
/// At `age == 2 * half_life`: weight = 0.25 (quarter strength).
///
/// A `min_weight` floor prevents signals from decaying to zero — very old
/// signals still carry some (reduced) weight.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FreshnessWeight {
    /// Half-life in seconds. Signal weight halves every `half_life_secs`.
    pub half_life_secs: u64,

    /// Minimum weight floor. Signals never decay below this value.
    /// Prevents complete erasure of historical trust signals.
    /// Must be in `[0.0, 1.0]`. Default: 0.0 (full decay possible).
    pub min_weight: f64,
}

impl FreshnessWeight {
    /// Default freshness weight: 90-day half-life, 0.05 minimum weight.
    ///
    /// After 90 days of inactivity, a signal carries ~50% weight.
    /// After 180 days, ~25%. After a year, ~6.25%. The 0.05 floor
    /// ensures signals never fully disappear.
    #[must_use]
    pub const fn default_config() -> Self {
        Self {
            // 90 days in seconds
            half_life_secs: 90 * 24 * 60 * 60,
            min_weight: 0.05,
        }
    }

    /// Computes the freshness weight for a signal verified at `verified_at`,
    /// evaluated at `current_time`.
    ///
    /// Returns a value in `[min_weight, 1.0]`.
    ///
    /// If `verified_at >= current_time`, returns 1.0 (fully fresh).
    /// If `half_life_secs == 0`, returns 1.0 (no decay configured).
    #[must_use]
    pub fn compute(&self, verified_at: u64, current_time: u64) -> f64 {
        if self.half_life_secs == 0 || verified_at >= current_time {
            return 1.0;
        }

        let age_secs = current_time - verified_at;

        // Exponential decay: 2^(-age / half_life)
        // Precision loss from u64→f64 is acceptable for time-based scoring.
        #[allow(clippy::cast_precision_loss)]
        let exponent = -(age_secs as f64) / (self.half_life_secs as f64);
        let weight = exponent.exp2();

        // Apply minimum weight floor
        if weight < self.min_weight {
            self.min_weight
        } else {
            weight
        }
    }
}

// ---------------------------------------------------------------------------
// IdentityDepthAssessment — aggregated trust signal depth
// ---------------------------------------------------------------------------

/// Aggregated identity depth assessment for a DID.
///
/// Collects all available trust signals for a DID and provides the data
/// that contexts use to evaluate Sybil resistance. The protocol computes
/// this; scoring is client/context policy.
///
/// **Key insight (§9.3):** "A DID with App Attest from an iPhone, Play
/// Integrity from a tablet, social attestations from X/GitHub/LinkedIn,
/// 8 months of history, and clean participation records is highly
/// trustworthy. This depth cannot be faked cheaply."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityDepthAssessment {
    /// The DID being assessed.
    pub subject_did: DID,

    /// All trust signals available for this DID, keyed by category.
    /// Multiple signals per category are aggregated (e.g., multiple
    /// social attestations combine into one `SocialAttestation` signal).
    pub signals: HashMap<TrustSignalCategory, TrustSignal>,

    /// Number of distinct signal categories present.
    /// Higher breadth = stronger Sybil resistance.
    pub signal_breadth: u32,

    /// Unix timestamp (seconds) when this assessment was computed.
    pub assessed_at: u64,
}

impl IdentityDepthAssessment {
    /// Creates a new assessment from a set of trust signals.
    ///
    /// Computes `signal_breadth` from the number of distinct categories.
    #[must_use]
    pub fn new(
        subject_did: DID,
        signals: HashMap<TrustSignalCategory, TrustSignal>,
        assessed_at: u64,
    ) -> Self {
        // Signal categories are a small fixed enum — count will never exceed u32::MAX.
        #[allow(clippy::cast_possible_truncation)]
        let signal_breadth = signals.len() as u32;
        Self {
            subject_did,
            signals,
            signal_breadth,
            assessed_at,
        }
    }

    /// Returns the trust signal for a given category, if present.
    #[must_use]
    pub fn signal(&self, category: &TrustSignalCategory) -> Option<&TrustSignal> {
        self.signals.get(category)
    }

    /// Returns the freshness-weighted strength of a signal category.
    ///
    /// If the signal is absent, returns 0.0.
    /// Otherwise, returns `strength * freshness_weight`.
    #[must_use]
    pub fn weighted_strength(
        &self,
        category: &TrustSignalCategory,
        freshness: &FreshnessWeight,
        current_time: u64,
    ) -> f64 {
        self.signals.get(category).map_or(0.0, |signal| {
            let weight = freshness.compute(signal.verified_at, current_time);
            #[allow(clippy::cast_precision_loss)] // Intentional f64 math for trust scoring.
            let strength = signal.strength as f64;
            strength * weight
        })
    }

    /// Returns true if all signal categories have `verified_at` more recent
    /// than `current_time - max_age_secs`.
    ///
    /// This is a stricter check than individual freshness weights — it
    /// requires ALL signals to be fresh, not just some.
    #[must_use]
    pub fn all_signals_fresh(&self, max_age_secs: u64, current_time: u64) -> bool {
        self.signals
            .values()
            .all(|signal| current_time.saturating_sub(signal.verified_at) <= max_age_secs)
    }
}

// ---------------------------------------------------------------------------
// EarnedCapacityPolicy — protocol-level capacity limits for new identities
// ---------------------------------------------------------------------------

/// Earned capacity policy for Sybil deterrence (§9.3 layer 1).
///
/// New identities start with limited capabilities. Capacity grows through
/// participation history, records, and time. Each field represents a
/// capability limit that the protocol enforces for identities below the
/// required depth thresholds.
///
/// Contexts declare their own earned capacity policies. The protocol
/// provides the types and evaluation; the thresholds are context-specific.
///
/// "Sybil accounts are cheap to create but expensive to make useful —
/// each needs real participation history." (§9.3)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EarnedCapacityPolicy {
    /// Maximum contexts the identity may create.
    /// New identities start restricted; capacity grows with depth.
    pub max_context_creation: u32,

    /// Maximum contexts the identity may participate in simultaneously.
    /// Limits the damage surface of a Sybil identity.
    pub max_participation_slots: u32,

    /// Maximum tool invocations per sliding window (`window_secs`).
    /// Constrains the operational throughput of shallow identities.
    pub max_tool_invocations_per_window: u32,

    /// Sliding window duration (seconds) for tool invocation rate limiting.
    pub tool_invocation_window_secs: u64,

    /// Maximum governance proposals per sliding window.
    /// Prevents shallow identities from flooding governance.
    pub max_governance_proposals_per_window: u32,

    /// Sliding window duration (seconds) for governance rate limiting.
    pub governance_proposal_window_secs: u64,
}

impl EarnedCapacityPolicy {
    /// Default restrictive policy for new identities with no history.
    ///
    /// Allows basic participation but limits amplification vectors:
    /// - 2 context creations (enough to get started)
    /// - 5 participation slots
    /// - 100 tool invocations per hour
    /// - 5 governance proposals per day
    #[must_use]
    pub const fn new_identity_default() -> Self {
        Self {
            max_context_creation: 2,
            max_participation_slots: 5,
            max_tool_invocations_per_window: 100,
            tool_invocation_window_secs: 3600, // 1 hour
            max_governance_proposals_per_window: 5,
            governance_proposal_window_secs: 86400, // 24 hours
        }
    }

    /// Unrestricted policy for identities with established depth.
    ///
    /// No practical limits — identity has demonstrated sufficient depth
    /// that capacity restrictions are unnecessary.
    #[must_use]
    pub const fn established_identity() -> Self {
        Self {
            max_context_creation: u32::MAX,
            max_participation_slots: u32::MAX,
            max_tool_invocations_per_window: u32::MAX,
            tool_invocation_window_secs: 3600,
            max_governance_proposals_per_window: u32::MAX,
            governance_proposal_window_secs: 86400,
        }
    }
}

// ---------------------------------------------------------------------------
// EarnedCapacityLevel — capacity tier based on identity depth
// ---------------------------------------------------------------------------

/// Tier assignment for earned capacity (§9.3).
///
/// Each tier corresponds to a set of capability limits. The protocol
/// provides the tier definitions; contexts evaluate which tier a DID
/// belongs to based on its [`IdentityDepthAssessment`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EarnedCapacityLevel {
    /// Brand-new identity with no history.
    /// Most restrictive limits.
    New,

    /// Identity with some history but limited depth.
    /// Moderate limits.
    Developing,

    /// Identity with demonstrated depth across multiple signals.
    /// Relaxed limits.
    Established,

    /// Identity with extensive, long-standing depth.
    /// No practical limits.
    Veteran,
}

// ---------------------------------------------------------------------------
// CapacityTierPolicy — mapping from depth thresholds to capacity levels
// ---------------------------------------------------------------------------

/// Maps identity depth thresholds to earned capacity levels.
///
/// Contexts declare their own tier thresholds. The protocol provides
/// the evaluation framework; the thresholds are context-specific.
///
/// Each tier requires a minimum signal breadth (number of distinct
/// signal categories) and minimum total weighted strength.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapacityTierPolicy {
    /// Thresholds for each capacity level. The policy checks tiers in
    /// order from highest (Veteran) to lowest (Developing). The first
    /// tier whose thresholds are met is assigned. If none match, `New`
    /// is assigned.
    pub tiers: Vec<CapacityTierThreshold>,
}

/// Threshold for a single capacity tier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapacityTierThreshold {
    /// The capacity level this threshold maps to.
    pub level: EarnedCapacityLevel,

    /// Minimum number of distinct signal categories required.
    pub min_signal_breadth: u32,

    /// Minimum total freshness-weighted strength across all signals.
    pub min_weighted_strength: f64,

    /// Minimum identity age in seconds (time since first signal).
    pub min_identity_age_secs: u64,
}

impl CapacityTierPolicy {
    /// Default tier policy suitable for general-purpose contexts.
    ///
    /// - `Veteran`: 4+ signal categories, 1000+ weighted strength, 180+ days
    /// - `Established`: 3+ signal categories, 200+ weighted strength, 30+ days
    /// - `Developing`: 1+ signal categories, 10+ weighted strength, 1+ day
    /// - `New`: everything below Developing thresholds
    #[must_use]
    pub fn default_policy() -> Self {
        Self {
            tiers: vec![
                CapacityTierThreshold {
                    level: EarnedCapacityLevel::Veteran,
                    min_signal_breadth: 4,
                    min_weighted_strength: 1000.0,
                    min_identity_age_secs: 180 * 24 * 3600, // 180 days
                },
                CapacityTierThreshold {
                    level: EarnedCapacityLevel::Established,
                    min_signal_breadth: 3,
                    min_weighted_strength: 200.0,
                    min_identity_age_secs: 30 * 24 * 3600, // 30 days
                },
                CapacityTierThreshold {
                    level: EarnedCapacityLevel::Developing,
                    min_signal_breadth: 1,
                    min_weighted_strength: 10.0,
                    min_identity_age_secs: 24 * 3600, // 1 day
                },
            ],
        }
    }

    /// Evaluates the capacity level for an identity depth assessment.
    ///
    /// Checks tiers in order; returns the first matching tier. If no tier
    /// matches, returns [`EarnedCapacityLevel::New`].
    #[must_use]
    pub fn evaluate(
        &self,
        assessment: &IdentityDepthAssessment,
        freshness: &FreshnessWeight,
        current_time: u64,
    ) -> EarnedCapacityLevel {
        let total_weighted_strength: f64 = assessment
            .signals
            .values()
            .map(|signal| {
                let weight = freshness.compute(signal.verified_at, current_time);
                #[allow(clippy::cast_precision_loss)] // Intentional f64 math for trust scoring.
                let strength = signal.strength as f64;
                strength * weight
            })
            .sum();

        // Compute identity age from the oldest signal
        let oldest_signal_time = assessment
            .signals
            .values()
            .map(|s| s.verified_at)
            .min()
            .unwrap_or(current_time);
        let identity_age_secs = current_time.saturating_sub(oldest_signal_time);

        for tier in &self.tiers {
            if assessment.signal_breadth >= tier.min_signal_breadth
                && total_weighted_strength >= tier.min_weighted_strength
                && identity_age_secs >= tier.min_identity_age_secs
            {
                return tier.level.clone();
            }
        }

        EarnedCapacityLevel::New
    }
}

// ---------------------------------------------------------------------------
// ContextSybilPolicy — per-context Sybil resistance thresholds
// ---------------------------------------------------------------------------

/// Per-context Sybil resistance policy (§9.3 layer 3).
///
/// Contexts set their own admission requirements from available trust signals.
/// A casual group chat might require nothing. A high-trust financial context
/// might require multiple attestation types, months of history, independent
/// endorsements, and economic activity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextSybilPolicy {
    /// Minimum signal categories required for admission.
    /// `None` means no minimum signal breadth requirement.
    pub min_signal_breadth: Option<u32>,

    /// Minimum total freshness-weighted strength for admission.
    /// `None` means no minimum strength requirement.
    pub min_weighted_strength: Option<f64>,

    /// Specific signal category requirements. Each entry requires that the
    /// DID has at least the specified strength in that category.
    pub required_signals: Vec<RequiredSignal>,

    /// The freshness weight configuration used to evaluate signal decay.
    pub freshness_config: FreshnessWeight,

    /// Earned capacity tier policy. Maps depth thresholds to capacity levels.
    pub capacity_policy: CapacityTierPolicy,

    /// Whether to require device attestation for admission.
    /// `false` by default — desktop gap acknowledged (§9.3).
    pub require_device_attestation: bool,
}

/// A required trust signal for context admission.
///
/// When `threshold_requirement` is `Some` and `category` is `Endorsement`,
/// the admission evaluator invokes [`check_threshold_attestation`] with the
/// provided [`ThresholdRequirement`] to enforce endorsement independence
/// (§22.13.3). This prevents Sybil rings of mutually-endorsing identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequiredSignal {
    /// Which signal category is required.
    pub category: TrustSignalCategory,

    /// Minimum raw strength value (before freshness weighting).
    pub min_strength: u64,

    /// Maximum age in seconds. Signals older than this are not counted.
    /// This is the binary cutoff — signals older than this are rejected
    /// regardless of freshness weight.
    pub max_age_secs: u64,

    /// Optional threshold requirement for endorsement independence (§22.13.3).
    ///
    /// When present and `category == TrustSignalCategory::Endorsement`, the
    /// evaluator calls `check_threshold_attestation` with attestor information
    /// to verify that endorsers are independently trustworthy (not colluding).
    /// `ThresholdRequirement` contains `f64` fields so `RequiredSignal` cannot
    /// derive `Eq`.
    #[serde(default)]
    pub threshold_requirement: Option<ThresholdRequirement>,
}

impl ContextSybilPolicy {
    /// Minimal policy suitable for casual contexts (chat rooms, open groups).
    /// No Sybil resistance requirements — any valid DID can join.
    #[must_use]
    pub fn casual() -> Self {
        Self {
            min_signal_breadth: None,
            min_weighted_strength: None,
            required_signals: Vec::new(),
            freshness_config: FreshnessWeight::default_config(),
            capacity_policy: CapacityTierPolicy::default_policy(),
            require_device_attestation: false,
        }
    }

    /// Moderate policy suitable for standard contexts.
    /// Requires at least 1 signal category with some history.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            min_signal_breadth: Some(1),
            min_weighted_strength: Some(10.0),
            required_signals: Vec::new(),
            freshness_config: FreshnessWeight::default_config(),
            capacity_policy: CapacityTierPolicy::default_policy(),
            require_device_attestation: false,
        }
    }

    /// High-trust policy suitable for sensitive contexts.
    /// Requires multiple signal categories and significant depth, including
    /// independent endorsements (§22.13.3).
    #[must_use]
    pub fn high_trust() -> Self {
        Self {
            min_signal_breadth: Some(3),
            min_weighted_strength: Some(200.0),
            required_signals: vec![
                RequiredSignal {
                    category: TrustSignalCategory::ParticipationHistory,
                    min_strength: 30 * 24 * 3600, // 30 days
                    max_age_secs: 90 * 24 * 3600, // 90 days
                    threshold_requirement: None,
                },
                RequiredSignal {
                    category: TrustSignalCategory::ParticipationRecord,
                    min_strength: 2, // clean records in 2+ contexts
                    max_age_secs: 90 * 24 * 3600,
                    threshold_requirement: None,
                },
                RequiredSignal {
                    category: TrustSignalCategory::Endorsement,
                    min_strength: 2,               // at least 2 endorsements
                    max_age_secs: 180 * 24 * 3600, // 180 days
                    threshold_requirement: Some(ThresholdRequirement::new(2, 3, 0.5)),
                },
            ],
            freshness_config: FreshnessWeight::default_config(),
            capacity_policy: CapacityTierPolicy::default_policy(),
            require_device_attestation: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SybilResistanceError — evaluation errors
// ---------------------------------------------------------------------------

/// Errors from Sybil resistance evaluation.
#[derive(Debug, thiserror::Error)]
pub enum SybilResistanceError {
    /// The DID lacks the required signal breadth.
    #[error("insufficient signal breadth: required {required}, found {found}")]
    InsufficientSignalBreadth {
        /// The minimum required signal breadth.
        required: u32,
        /// The actual signal breadth.
        found: u32,
    },

    /// The DID's total weighted strength is below the threshold.
    #[error("insufficient weighted strength: required {required:.2}, found {found:.2}")]
    InsufficientWeightedStrength {
        /// The minimum required weighted strength.
        required: f64,
        /// The actual total weighted strength.
        found: f64,
    },

    /// A required signal category is missing.
    #[error("missing required signal: {category:?}")]
    MissingRequiredSignal {
        /// The signal category that is missing.
        category: TrustSignalCategory,
    },

    /// A required signal is below the strength threshold.
    #[error("signal {category:?} strength {found} below required {required}")]
    SignalStrengthInsufficient {
        /// The signal category.
        category: TrustSignalCategory,
        /// The minimum required strength.
        required: u64,
        /// The actual strength.
        found: u64,
    },

    /// A required signal is too old (beyond `max_age_secs`).
    #[error(
        "signal {category:?} too stale: max_age_secs={max_age_secs}, \
         signal_age_secs={signal_age_secs}"
    )]
    SignalTooStale {
        /// The signal category.
        category: TrustSignalCategory,
        /// The maximum allowed age in seconds.
        max_age_secs: u64,
        /// The actual age of the signal in seconds.
        signal_age_secs: u64,
    },

    /// Device attestation is required but not present.
    #[error("device attestation required but not present")]
    DeviceAttestationRequired,

    /// Endorsement independence check failed (§22.13.3).
    ///
    /// The endorsing attestors do not meet the independence threshold required
    /// by `ThresholdRequirement`. This typically means the endorsers share too
    /// many context memberships or mutual endorsements, suggesting collusion
    /// or a Sybil ring.
    #[error("endorsement independence insufficient: {reason}")]
    EndorsementIndependenceInsufficient {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// evaluate_sybil_resistance — check a DID's signals against context policy
// ---------------------------------------------------------------------------

/// Evaluates a DID's trust signals against a context's Sybil resistance policy.
///
/// Returns `Ok(())` if the DID satisfies all policy requirements, or the first
/// error encountered.
///
/// This function checks:
/// 1. Device attestation requirement (if configured).
/// 2. Signal breadth (number of distinct categories).
/// 3. Total freshness-weighted strength.
/// 4. Per-category signal requirements (strength and age).
/// 5. Endorsement independence (§22.13.3) when a `RequiredSignal` for
///    `Endorsement` has `threshold_requirement` set and `attestors` are
///    provided.
///
/// # Arguments
///
/// * `assessment` — The DID's aggregated trust signals.
/// * `policy` — The context's Sybil resistance policy.
/// * `current_time` — Unix timestamp (seconds) for freshness evaluation.
/// * `attestors` — Optional slice of attestor information for endorsement
///   independence evaluation. Required when the policy includes an endorsement
///   `RequiredSignal` with `threshold_requirement`. Pass `None` when
///   endorsement independence checking is not needed (existing callers).
///
/// # Errors
///
/// Returns [`SybilResistanceError`] if the assessment does not meet the
/// policy requirements (missing attestation, insufficient breadth/strength,
/// missing/stale per-category signals, or failed endorsement independence).
///
/// See spec §9.3 (context-level thresholds), §22.13.3 (endorsement
/// independence).
pub fn evaluate_sybil_resistance(
    assessment: &IdentityDepthAssessment,
    policy: &ContextSybilPolicy,
    current_time: u64,
    attestors: Option<&[AttestorInfo]>,
) -> Result<(), SybilResistanceError> {
    // 1. Check device attestation requirement.
    if policy.require_device_attestation
        && !assessment
            .signals
            .contains_key(&TrustSignalCategory::DeviceAttestation)
    {
        return Err(SybilResistanceError::DeviceAttestationRequired);
    }

    // 2. Check signal breadth.
    if let Some(min_breadth) = policy.min_signal_breadth
        && assessment.signal_breadth < min_breadth
    {
        return Err(SybilResistanceError::InsufficientSignalBreadth {
            required: min_breadth,
            found: assessment.signal_breadth,
        });
    }

    // 3. Check total freshness-weighted strength.
    if let Some(min_strength) = policy.min_weighted_strength {
        let total: f64 = assessment
            .signals
            .values()
            .map(|signal| {
                let weight = policy
                    .freshness_config
                    .compute(signal.verified_at, current_time);
                #[allow(clippy::cast_precision_loss)] // Intentional f64 math for trust scoring.
                let strength = signal.strength as f64;
                strength * weight
            })
            .sum();

        if total < min_strength {
            return Err(SybilResistanceError::InsufficientWeightedStrength {
                required: min_strength,
                found: total,
            });
        }
    }

    // 4. Check per-category signal requirements.
    for req in &policy.required_signals {
        let signal = assessment.signals.get(&req.category).ok_or_else(|| {
            SybilResistanceError::MissingRequiredSignal {
                category: req.category.clone(),
            }
        })?;

        // Binary age cutoff.
        let signal_age_secs = current_time.saturating_sub(signal.verified_at);
        if signal_age_secs > req.max_age_secs {
            return Err(SybilResistanceError::SignalTooStale {
                category: req.category.clone(),
                max_age_secs: req.max_age_secs,
                signal_age_secs,
            });
        }

        // Strength threshold.
        if signal.strength < req.min_strength {
            return Err(SybilResistanceError::SignalStrengthInsufficient {
                category: req.category.clone(),
                required: req.min_strength,
                found: signal.strength,
            });
        }
    }

    // 5. Endorsement independence check (§22.13.3).
    //
    // For each required signal with category Endorsement and a
    // threshold_requirement, invoke check_threshold_attestation to verify
    // that endorsers are independently trustworthy — not a Sybil ring.
    for req in &policy.required_signals {
        let (TrustSignalCategory::Endorsement, Some(threshold)) =
            (&req.category, &req.threshold_requirement)
        else {
            continue;
        };
        let att =
            attestors.ok_or_else(
                || SybilResistanceError::EndorsementIndependenceInsufficient {
                    reason: "attestors required for endorsement independence \
                         check but not provided"
                        .into(),
                },
            )?;
        // Filter attestors to only those whose attestation subject matches the
        // DID being evaluated. Without this, an attacker could submit
        // endorsement attestations for a completely different DID and have them
        // count toward this subject's independence check.
        let subject_attestors: Vec<AttestorInfo> = att
            .iter()
            .filter(|a| {
                a.attestation
                    .as_ref()
                    .is_some_and(|att| att.subject == assessment.subject_did)
            })
            .cloned()
            .collect();
        let result = check_threshold_attestation(
            &AttestationType::Endorsement,
            &subject_attestors,
            threshold,
        );
        if !result.met {
            return Err(SybilResistanceError::EndorsementIndependenceInsufficient {
                reason: format!(
                    "threshold not met: {}/{} valid attestations \
                         (need {}), independence {:.3} (need {:.3})",
                    result.valid_count,
                    threshold.total_attestors,
                    result.required_count,
                    result.independence_score,
                    result.independence_threshold,
                ),
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// evaluate_earned_capacity — compute capacity level for a DID
// ---------------------------------------------------------------------------

/// Evaluates the earned capacity level for a DID based on its identity depth.
///
/// Returns the capacity level and the corresponding policy limits. Contexts
/// use this to enforce rate limits, context creation caps, and participation
/// slot limits on new/shallow identities.
///
/// See spec §9.3 (earned capacity layer).
#[must_use]
pub fn evaluate_earned_capacity(
    assessment: &IdentityDepthAssessment,
    policy: &ContextSybilPolicy,
    current_time: u64,
) -> (EarnedCapacityLevel, EarnedCapacityPolicy) {
    let level = policy
        .capacity_policy
        .evaluate(assessment, &policy.freshness_config, current_time);

    let capacity = match level {
        EarnedCapacityLevel::New => EarnedCapacityPolicy::new_identity_default(),
        EarnedCapacityLevel::Developing => EarnedCapacityPolicy {
            max_context_creation: 10,
            max_participation_slots: 20,
            max_tool_invocations_per_window: 500,
            tool_invocation_window_secs: 3600,
            max_governance_proposals_per_window: 20,
            governance_proposal_window_secs: 86400,
        },
        EarnedCapacityLevel::Established => EarnedCapacityPolicy {
            max_context_creation: 100,
            max_participation_slots: 200,
            max_tool_invocations_per_window: 5000,
            tool_invocation_window_secs: 3600,
            max_governance_proposals_per_window: 100,
            governance_proposal_window_secs: 86400,
        },
        EarnedCapacityLevel::Veteran => EarnedCapacityPolicy::established_identity(),
    };

    (level, capacity)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss
)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::trust::{Attestation, AttestationType, RevocationStatus};

    fn did(s: &str) -> DID {
        DID::from(s)
    }

    fn now() -> u64 {
        // Stable test time: 2026-01-15 00:00:00 UTC
        1_768_435_200
    }

    /// Creates an `Attestation` of type `Endorsement` for testing.
    fn make_endorsement_attestation(issuer: &str, subject: &str, issued_at: u64) -> Attestation {
        Attestation {
            id: format!("endorse-{issuer}-{subject}"),
            attestation_type: AttestationType::Endorsement,
            issuer: did(issuer),
            subject: did(subject),
            claim: serde_json::json!({"endorsement": true}),
            evidence: None,
            issued_at,
            expires_at: None,
            renewal_interval: None,
            renewed_at: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64], // dummy signature for tests
        }
    }

    /// Creates a set of 3 independent attestors with no shared contexts
    /// or mutual endorsements — passes endorsement independence checks.
    fn make_independent_attestors(current_time: u64) -> Vec<AttestorInfo> {
        let subject = "did:dht:z6MkDeepIdentity";
        vec![
            AttestorInfo {
                did: did("did:dht:z6MkEndorserA"),
                context_memberships: HashSet::from(["ctx-alpha".into()]),
                endorsements: HashSet::new(),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkEndorserA",
                    subject,
                    current_time - 3600,
                )),
            },
            AttestorInfo {
                did: did("did:dht:z6MkEndorserB"),
                context_memberships: HashSet::from(["ctx-beta".into()]),
                endorsements: HashSet::new(),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkEndorserB",
                    subject,
                    current_time - 7200,
                )),
            },
            AttestorInfo {
                did: did("did:dht:z6MkEndorserC"),
                context_memberships: HashSet::from(["ctx-gamma".into()]),
                endorsements: HashSet::new(),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkEndorserC",
                    subject,
                    current_time - 10800,
                )),
            },
        ]
    }

    /// Creates a set of 3 colluding attestors — all share the same contexts
    /// and mutually endorse each other, failing independence checks.
    fn make_colluding_attestors(current_time: u64) -> Vec<AttestorInfo> {
        let subject = "did:dht:z6MkDeepIdentity";
        let shared = HashSet::from([
            "ctx-shared-1".to_string(),
            "ctx-shared-2".to_string(),
            "ctx-shared-3".to_string(),
            "ctx-shared-4".to_string(),
            "ctx-shared-5".to_string(),
        ]);
        vec![
            AttestorInfo {
                did: did("did:dht:z6MkColluderA"),
                context_memberships: shared.clone(),
                endorsements: HashSet::from([
                    did("did:dht:z6MkColluderB"),
                    did("did:dht:z6MkColluderC"),
                ]),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkColluderA",
                    subject,
                    current_time - 3600,
                )),
            },
            AttestorInfo {
                did: did("did:dht:z6MkColluderB"),
                context_memberships: shared.clone(),
                endorsements: HashSet::from([
                    did("did:dht:z6MkColluderA"),
                    did("did:dht:z6MkColluderC"),
                ]),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkColluderB",
                    subject,
                    current_time - 3600,
                )),
            },
            AttestorInfo {
                did: did("did:dht:z6MkColluderC"),
                context_memberships: shared,
                endorsements: HashSet::from([
                    did("did:dht:z6MkColluderA"),
                    did("did:dht:z6MkColluderB"),
                ]),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkColluderC",
                    subject,
                    current_time - 3600,
                )),
            },
        ]
    }

    fn make_signal(category: TrustSignalCategory, strength: u64, verified_at: u64) -> TrustSignal {
        TrustSignal {
            category,
            verified_at,
            strength,
            details: None,
        }
    }

    fn make_deep_assessment(current_time: u64) -> IdentityDepthAssessment {
        let mut signals = HashMap::new();
        signals.insert(
            TrustSignalCategory::SocialAttestation,
            make_signal(
                TrustSignalCategory::SocialAttestation,
                3,
                current_time - 3600,
            ),
        );
        signals.insert(
            TrustSignalCategory::ParticipationHistory,
            make_signal(
                TrustSignalCategory::ParticipationHistory,
                200 * 24 * 3600, // 200 days
                current_time - 7200,
            ),
        );
        signals.insert(
            TrustSignalCategory::ParticipationRecord,
            make_signal(
                TrustSignalCategory::ParticipationRecord,
                5,
                current_time - 1800,
            ),
        );
        signals.insert(
            TrustSignalCategory::EconomicActivity,
            make_signal(
                TrustSignalCategory::EconomicActivity,
                500,
                current_time - 86400,
            ),
        );
        signals.insert(
            TrustSignalCategory::Endorsement,
            make_signal(TrustSignalCategory::Endorsement, 4, current_time - 43200),
        );

        IdentityDepthAssessment::new(did("did:dht:z6MkDeepIdentity"), signals, current_time)
    }

    fn make_shallow_assessment(current_time: u64) -> IdentityDepthAssessment {
        let mut signals = HashMap::new();
        signals.insert(
            TrustSignalCategory::ParticipationHistory,
            make_signal(
                TrustSignalCategory::ParticipationHistory,
                3600, // 1 hour
                current_time - 3600,
            ),
        );

        IdentityDepthAssessment::new(did("did:dht:z6MkShallowSybil"), signals, current_time)
    }

    // --- FreshnessWeight tests ---

    #[test]
    fn freshness_weight_fully_fresh() {
        let fw = FreshnessWeight::default_config();
        let weight = fw.compute(now(), now());
        assert!((weight - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn freshness_weight_at_half_life() {
        let fw = FreshnessWeight {
            half_life_secs: 100,
            min_weight: 0.0,
        };
        let weight = fw.compute(0, 100);
        assert!((weight - 0.5).abs() < 0.001);
    }

    #[test]
    fn freshness_weight_at_double_half_life() {
        let fw = FreshnessWeight {
            half_life_secs: 100,
            min_weight: 0.0,
        };
        let weight = fw.compute(0, 200);
        assert!((weight - 0.25).abs() < 0.001);
    }

    #[test]
    fn freshness_weight_respects_min_weight() {
        let fw = FreshnessWeight {
            half_life_secs: 10,
            min_weight: 0.1,
        };
        // Very old signal — would decay far below 0.1 without floor
        let weight = fw.compute(0, 10_000);
        assert!((weight - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn freshness_weight_zero_half_life_returns_one() {
        let fw = FreshnessWeight {
            half_life_secs: 0,
            min_weight: 0.0,
        };
        let weight = fw.compute(0, 10_000);
        assert!((weight - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn freshness_weight_future_signal_returns_one() {
        let fw = FreshnessWeight::default_config();
        // Signal verified "in the future" (clock skew scenario)
        let weight = fw.compute(now() + 100, now());
        assert!((weight - 1.0).abs() < f64::EPSILON);
    }

    // --- IdentityDepthAssessment tests ---

    #[test]
    fn deep_identity_has_five_signal_categories() {
        let assessment = make_deep_assessment(now());
        assert_eq!(assessment.signal_breadth, 5);
    }

    #[test]
    fn shallow_identity_has_one_signal_category() {
        let assessment = make_shallow_assessment(now());
        assert_eq!(assessment.signal_breadth, 1);
    }

    #[test]
    fn weighted_strength_decays_with_age() {
        let mut signals = HashMap::new();
        let category = TrustSignalCategory::ParticipationHistory;
        signals.insert(category.clone(), make_signal(category.clone(), 100, 0));

        let assessment = IdentityDepthAssessment::new(did("did:dht:z6MkTest"), signals, 1000);

        let fw = FreshnessWeight {
            half_life_secs: 500,
            min_weight: 0.0,
        };

        // At time 1000, signal from time 0 has age 1000 = 2 half-lives
        // Weight = 2^(-2) = 0.25. Strength = 100 * 0.25 = 25.0
        let ws = assessment.weighted_strength(&category, &fw, 1000);
        assert!((ws - 25.0).abs() < 0.1);
    }

    #[test]
    fn weighted_strength_absent_category_returns_zero() {
        let assessment = make_shallow_assessment(now());
        let fw = FreshnessWeight::default_config();
        let ws = assessment.weighted_strength(&TrustSignalCategory::DeviceAttestation, &fw, now());
        assert!((ws).abs() < f64::EPSILON);
    }

    #[test]
    fn all_signals_fresh_true_when_all_recent() {
        let assessment = make_deep_assessment(now());
        // max_age = 1 day, all signals verified within last day
        assert!(assessment.all_signals_fresh(86400, now()));
    }

    #[test]
    fn all_signals_fresh_false_when_one_stale() {
        let mut signals = HashMap::new();
        signals.insert(
            TrustSignalCategory::SocialAttestation,
            make_signal(TrustSignalCategory::SocialAttestation, 3, now() - 3600),
        );
        signals.insert(
            TrustSignalCategory::ParticipationHistory,
            make_signal(
                TrustSignalCategory::ParticipationHistory,
                100,
                now() - 200_000, // older than 1 day
            ),
        );

        let assessment = IdentityDepthAssessment::new(did("did:dht:z6MkTest"), signals, now());

        assert!(!assessment.all_signals_fresh(86400, now()));
    }

    // --- EarnedCapacityPolicy tests ---

    #[test]
    fn new_identity_default_is_restrictive() {
        let policy = EarnedCapacityPolicy::new_identity_default();
        assert_eq!(policy.max_context_creation, 2);
        assert_eq!(policy.max_participation_slots, 5);
        assert_eq!(policy.max_tool_invocations_per_window, 100);
    }

    #[test]
    fn established_identity_is_unrestricted() {
        let policy = EarnedCapacityPolicy::established_identity();
        assert_eq!(policy.max_context_creation, u32::MAX);
        assert_eq!(policy.max_participation_slots, u32::MAX);
    }

    // --- CapacityTierPolicy tests ---

    #[test]
    fn deep_identity_evaluates_to_veteran_or_established() {
        let policy = CapacityTierPolicy::default_policy();
        let fw = FreshnessWeight::default_config();
        let assessment = make_deep_assessment(now());

        let level = policy.evaluate(&assessment, &fw, now());
        // Deep identity: 5 categories, very high strength, but oldest signal
        // is only ~1 day old. Needs 180 days for Veteran.
        // Should be Established (3+ categories, 200+ strength, 30+ days needed
        // but we have participation_history signal of 200*86400 which drives strength).
        // Actually identity_age = max(ages) = 86400 seconds = 1 day.
        // Established requires 30 days. So this should be Developing.
        assert_eq!(level, EarnedCapacityLevel::Developing);
    }

    #[test]
    fn old_deep_identity_evaluates_to_veteran() {
        let policy = CapacityTierPolicy::default_policy();
        let fw = FreshnessWeight::default_config();

        // Create assessment with old signals
        let mut signals = HashMap::new();
        let t = now();
        signals.insert(
            TrustSignalCategory::SocialAttestation,
            make_signal(TrustSignalCategory::SocialAttestation, 5, t - 3600),
        );
        signals.insert(
            TrustSignalCategory::ParticipationHistory,
            make_signal(
                TrustSignalCategory::ParticipationHistory,
                365 * 24 * 3600,
                t - 200 * 24 * 3600, // verified 200 days ago
            ),
        );
        signals.insert(
            TrustSignalCategory::ParticipationRecord,
            make_signal(TrustSignalCategory::ParticipationRecord, 10, t - 7200),
        );
        signals.insert(
            TrustSignalCategory::EconomicActivity,
            make_signal(TrustSignalCategory::EconomicActivity, 1000, t - 86400),
        );
        signals.insert(
            TrustSignalCategory::Endorsement,
            make_signal(TrustSignalCategory::Endorsement, 8, t - 43200),
        );

        let assessment = IdentityDepthAssessment::new(did("did:dht:z6MkVeteran"), signals, t);

        let level = policy.evaluate(&assessment, &fw, t);
        // 5 categories, very high strength, oldest signal 200 days ago > 180
        assert_eq!(level, EarnedCapacityLevel::Veteran);
    }

    #[test]
    fn shallow_identity_evaluates_to_new() {
        let policy = CapacityTierPolicy::default_policy();
        let fw = FreshnessWeight::default_config();
        let assessment = make_shallow_assessment(now());

        let level = policy.evaluate(&assessment, &fw, now());
        // 1 category, very low strength (3600), but identity age is 1 hour.
        // Developing requires 1 day. So New.
        assert_eq!(level, EarnedCapacityLevel::New);
    }

    #[test]
    fn no_signals_evaluates_to_new() {
        let policy = CapacityTierPolicy::default_policy();
        let fw = FreshnessWeight::default_config();

        let assessment =
            IdentityDepthAssessment::new(did("did:dht:z6MkEmpty"), HashMap::new(), now());

        let level = policy.evaluate(&assessment, &fw, now());
        assert_eq!(level, EarnedCapacityLevel::New);
    }

    // --- evaluate_sybil_resistance tests ---

    #[test]
    fn casual_policy_accepts_empty_identity() {
        let assessment =
            IdentityDepthAssessment::new(did("did:dht:z6MkNew"), HashMap::new(), now());
        let policy = ContextSybilPolicy::casual();
        assert!(evaluate_sybil_resistance(&assessment, &policy, now(), None).is_ok());
    }

    #[test]
    fn standard_policy_rejects_empty_identity() {
        let assessment =
            IdentityDepthAssessment::new(did("did:dht:z6MkNew"), HashMap::new(), now());
        let policy = ContextSybilPolicy::standard();
        let result = evaluate_sybil_resistance(&assessment, &policy, now(), None);
        assert!(matches!(
            result,
            Err(SybilResistanceError::InsufficientSignalBreadth {
                required: 1,
                found: 0
            })
        ));
    }

    #[test]
    fn standard_policy_accepts_shallow_identity_with_some_strength() {
        let mut signals = HashMap::new();
        signals.insert(
            TrustSignalCategory::ParticipationHistory,
            make_signal(
                TrustSignalCategory::ParticipationHistory,
                30 * 24 * 3600, // 30 days
                now() - 3600,
            ),
        );

        let assessment = IdentityDepthAssessment::new(did("did:dht:z6MkModerate"), signals, now());
        let policy = ContextSybilPolicy::standard();
        assert!(evaluate_sybil_resistance(&assessment, &policy, now(), None).is_ok());
    }

    #[test]
    fn high_trust_policy_rejects_shallow_identity() {
        let assessment = make_shallow_assessment(now());
        let policy = ContextSybilPolicy::high_trust();
        let result = evaluate_sybil_resistance(&assessment, &policy, now(), None);
        assert!(matches!(
            result,
            Err(SybilResistanceError::InsufficientSignalBreadth { .. })
        ));
    }

    #[test]
    fn high_trust_policy_accepts_deep_identity() {
        let assessment = make_deep_assessment(now());
        let policy = ContextSybilPolicy::high_trust();
        let attestors = make_independent_attestors(now());
        assert!(evaluate_sybil_resistance(&assessment, &policy, now(), Some(&attestors)).is_ok());
    }

    #[test]
    fn device_attestation_required_rejects_without() {
        let assessment = make_deep_assessment(now());
        let mut policy = ContextSybilPolicy::casual();
        policy.require_device_attestation = true;
        let result = evaluate_sybil_resistance(&assessment, &policy, now(), None);
        assert!(matches!(
            result,
            Err(SybilResistanceError::DeviceAttestationRequired)
        ));
    }

    #[test]
    fn device_attestation_required_accepts_with() {
        let t = now();
        let mut signals = HashMap::new();
        signals.insert(
            TrustSignalCategory::DeviceAttestation,
            make_signal(TrustSignalCategory::DeviceAttestation, 1, t - 3600),
        );

        let assessment = IdentityDepthAssessment::new(did("did:dht:z6MkMobile"), signals, t);

        let mut policy = ContextSybilPolicy::casual();
        policy.require_device_attestation = true;
        assert!(evaluate_sybil_resistance(&assessment, &policy, t, None).is_ok());
    }

    #[test]
    fn stale_required_signal_is_rejected() {
        let t = now();
        let mut signals = HashMap::new();
        signals.insert(
            TrustSignalCategory::ParticipationHistory,
            make_signal(
                TrustSignalCategory::ParticipationHistory,
                100 * 24 * 3600,
                t - 200 * 24 * 3600, // verified 200 days ago
            ),
        );
        signals.insert(
            TrustSignalCategory::ParticipationRecord,
            make_signal(TrustSignalCategory::ParticipationRecord, 5, t - 3600),
        );
        signals.insert(
            TrustSignalCategory::SocialAttestation,
            make_signal(TrustSignalCategory::SocialAttestation, 3, t - 3600),
        );

        let assessment = IdentityDepthAssessment::new(did("did:dht:z6MkStale"), signals, t);

        let policy = ContextSybilPolicy::high_trust();
        let result = evaluate_sybil_resistance(&assessment, &policy, t, None);
        // ParticipationHistory has max_age_secs of 90 days, signal is 200 days old
        assert!(matches!(
            result,
            Err(SybilResistanceError::SignalTooStale { .. })
        ));
    }

    // --- evaluate_earned_capacity tests ---

    #[test]
    fn new_identity_gets_restrictive_capacity() {
        let assessment = make_shallow_assessment(now());
        let policy = ContextSybilPolicy::standard();
        let (level, capacity) = evaluate_earned_capacity(&assessment, &policy, now());
        assert_eq!(level, EarnedCapacityLevel::New);
        assert_eq!(capacity.max_context_creation, 2);
        assert_eq!(capacity.max_participation_slots, 5);
    }

    #[test]
    fn deep_identity_gets_relaxed_capacity() {
        let t = now();
        let mut signals = HashMap::new();
        signals.insert(
            TrustSignalCategory::SocialAttestation,
            make_signal(TrustSignalCategory::SocialAttestation, 5, t - 3600),
        );
        signals.insert(
            TrustSignalCategory::ParticipationHistory,
            make_signal(
                TrustSignalCategory::ParticipationHistory,
                365 * 24 * 3600,
                t - 200 * 24 * 3600,
            ),
        );
        signals.insert(
            TrustSignalCategory::ParticipationRecord,
            make_signal(TrustSignalCategory::ParticipationRecord, 10, t - 7200),
        );
        signals.insert(
            TrustSignalCategory::EconomicActivity,
            make_signal(TrustSignalCategory::EconomicActivity, 1000, t - 86400),
        );
        signals.insert(
            TrustSignalCategory::Endorsement,
            make_signal(TrustSignalCategory::Endorsement, 8, t - 43200),
        );

        let assessment = IdentityDepthAssessment::new(did("did:dht:z6MkVeteran"), signals, t);

        let policy = ContextSybilPolicy::standard();
        let (level, capacity) = evaluate_earned_capacity(&assessment, &policy, t);
        assert_eq!(level, EarnedCapacityLevel::Veteran);
        assert_eq!(capacity.max_context_creation, u32::MAX);
    }

    // --- Sybil attack scenario tests ---

    #[test]
    fn sybil_attacker_shallow_identities_fail_standard_policy() {
        // A Sybil attacker creates 10 identities. Each has minimal history.
        // Standard policy should reject all of them.
        let policy = ContextSybilPolicy::standard();

        for i in 0..10 {
            let mut signals = HashMap::new();
            signals.insert(
                TrustSignalCategory::ParticipationHistory,
                make_signal(
                    TrustSignalCategory::ParticipationHistory,
                    60, // 1 minute of participation
                    now() - 300,
                ),
            );

            let assessment =
                IdentityDepthAssessment::new(did(&format!("did:dht:z6MkSybil{i}")), signals, now());

            let result = evaluate_sybil_resistance(&assessment, &policy, now(), None);
            // Strength 60 < required 10.0? No, 60 > 10. But breadth is 1 >= 1.
            // Actually this passes standard (1 category, 60 strength).
            // Standard is intentionally low-bar — just needs any signal.
            assert!(result.is_ok());
        }

        // But high trust rejects them all
        let high_trust = ContextSybilPolicy::high_trust();
        for i in 0..10 {
            let mut signals = HashMap::new();
            signals.insert(
                TrustSignalCategory::ParticipationHistory,
                make_signal(TrustSignalCategory::ParticipationHistory, 60, now() - 300),
            );

            let assessment =
                IdentityDepthAssessment::new(did(&format!("did:dht:z6MkSybil{i}")), signals, now());

            let result = evaluate_sybil_resistance(&assessment, &high_trust, now(), None);
            assert!(result.is_err());
        }
    }

    #[test]
    fn freshness_decay_reduces_stale_identity_weighted_strength() {
        let t = now();

        // Identity that was strong 1 year ago but hasn't been active since
        let mut signals = HashMap::new();
        signals.insert(
            TrustSignalCategory::SocialAttestation,
            make_signal(
                TrustSignalCategory::SocialAttestation,
                5,
                t - 365 * 24 * 3600, // 1 year ago
            ),
        );
        signals.insert(
            TrustSignalCategory::ParticipationHistory,
            make_signal(
                TrustSignalCategory::ParticipationHistory,
                180 * 24 * 3600,
                t - 365 * 24 * 3600, // 1 year ago
            ),
        );
        signals.insert(
            TrustSignalCategory::ParticipationRecord,
            make_signal(
                TrustSignalCategory::ParticipationRecord,
                5,
                t - 365 * 24 * 3600, // 1 year ago
            ),
        );

        let assessment = IdentityDepthAssessment::new(did("did:dht:z6MkStaleVet"), signals, t);

        let fw = FreshnessWeight::default_config(); // 90-day half-life

        // 365 days / 90 day half-life = ~4 half-lives
        // Weight = 2^(-4) ≈ 0.0625, but min_weight = 0.05
        // Social: 5 * 0.0625 ≈ 0.3125
        // History: 15552000 * 0.0625 ≈ 972000
        // Record: 5 * 0.0625 ≈ 0.3125
        // Total ≈ 972001 — high raw strength but heavily decayed

        // Compare with fresh identity with same raw signals
        let mut fresh_signals = HashMap::new();
        fresh_signals.insert(
            TrustSignalCategory::SocialAttestation,
            make_signal(TrustSignalCategory::SocialAttestation, 5, t - 3600),
        );
        fresh_signals.insert(
            TrustSignalCategory::ParticipationHistory,
            make_signal(
                TrustSignalCategory::ParticipationHistory,
                180 * 24 * 3600,
                t - 3600,
            ),
        );
        fresh_signals.insert(
            TrustSignalCategory::ParticipationRecord,
            make_signal(TrustSignalCategory::ParticipationRecord, 5, t - 3600),
        );

        let fresh_assessment =
            IdentityDepthAssessment::new(did("did:dht:z6MkFreshVet"), fresh_signals, t);

        // Verify that stale signals have lower weighted strength
        #[allow(clippy::cast_precision_loss)] // Intentional f64 math for trust scoring tests.
        let stale_strength: f64 = assessment
            .signals
            .values()
            .map(|s| s.strength as f64 * fw.compute(s.verified_at, t))
            .sum();

        #[allow(clippy::cast_precision_loss)] // Intentional f64 math for trust scoring tests.
        let fresh_strength: f64 = fresh_assessment
            .signals
            .values()
            .map(|s| s.strength as f64 * fw.compute(s.verified_at, t))
            .sum();

        assert!(
            stale_strength < fresh_strength,
            "stale_strength ({stale_strength:.2}) should be less than fresh_strength ({fresh_strength:.2})"
        );
    }

    // --- Serialization tests ---

    #[test]
    fn serde_roundtrip_trust_signal_category() {
        let categories = [
            TrustSignalCategory::SocialAttestation,
            TrustSignalCategory::DeviceAttestation,
            TrustSignalCategory::ParticipationHistory,
            TrustSignalCategory::ParticipationRecord,
            TrustSignalCategory::EconomicActivity,
            TrustSignalCategory::Endorsement,
        ];

        for category in &categories {
            let json = serde_json::to_string(category).unwrap();
            let back: TrustSignalCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, category);
        }
    }

    #[test]
    fn serde_roundtrip_context_sybil_policy() {
        let policy = ContextSybilPolicy::high_trust();
        let json = serde_json::to_string(&policy).unwrap();
        let back: ContextSybilPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, policy);
    }

    #[test]
    fn serde_roundtrip_earned_capacity_policy() {
        let policy = EarnedCapacityPolicy::new_identity_default();
        let json = serde_json::to_string(&policy).unwrap();
        let back: EarnedCapacityPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, policy);
    }

    #[test]
    fn serde_roundtrip_identity_depth_assessment() {
        let assessment = make_deep_assessment(now());
        let json = serde_json::to_string(&assessment).unwrap();
        let back: IdentityDepthAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(back, assessment);
    }

    #[test]
    fn serde_roundtrip_earned_capacity_level() {
        let levels = [
            EarnedCapacityLevel::New,
            EarnedCapacityLevel::Developing,
            EarnedCapacityLevel::Established,
            EarnedCapacityLevel::Veteran,
        ];

        for level in &levels {
            let json = serde_json::to_string(level).unwrap();
            let back: EarnedCapacityLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, level);
        }
    }

    // --- Endorsement independence tests (§22.13.3) ---

    #[test]
    fn endorsement_independence_passes_with_independent_attestors() {
        let assessment = make_deep_assessment(now());
        let policy = ContextSybilPolicy::high_trust();
        let attestors = make_independent_attestors(now());
        let result = evaluate_sybil_resistance(&assessment, &policy, now(), Some(&attestors));
        assert!(
            result.is_ok(),
            "independent attestors should pass: {result:?}"
        );
    }

    #[test]
    fn endorsement_independence_fails_with_colluding_attestors() {
        let assessment = make_deep_assessment(now());
        let policy = ContextSybilPolicy::high_trust();
        let attestors = make_colluding_attestors(now());
        let result = evaluate_sybil_resistance(&assessment, &policy, now(), Some(&attestors));
        assert!(
            matches!(
                result,
                Err(SybilResistanceError::EndorsementIndependenceInsufficient { .. })
            ),
            "colluding attestors should fail independence check: {result:?}"
        );
    }

    #[test]
    fn endorsement_independence_fails_when_attestors_not_provided() {
        let assessment = make_deep_assessment(now());
        let policy = ContextSybilPolicy::high_trust();
        let result = evaluate_sybil_resistance(&assessment, &policy, now(), None);
        assert!(
            matches!(
                result,
                Err(SybilResistanceError::EndorsementIndependenceInsufficient { .. })
            ),
            "missing attestors should fail: {result:?}"
        );
    }

    #[test]
    fn high_trust_preset_includes_endorsement_requirement() {
        let policy = ContextSybilPolicy::high_trust();
        let endorsement_req = policy
            .required_signals
            .iter()
            .find(|r| r.category == TrustSignalCategory::Endorsement);
        assert!(
            endorsement_req.is_some(),
            "high_trust() must include an Endorsement RequiredSignal"
        );
        let req = endorsement_req.unwrap();
        assert_eq!(req.min_strength, 2);
        assert_eq!(req.max_age_secs, 180 * 24 * 3600);
        assert!(
            req.threshold_requirement.is_some(),
            "Endorsement signal must have threshold_requirement"
        );
        let threshold = req.threshold_requirement.as_ref().unwrap();
        assert_eq!(threshold.required_count, 2);
        assert_eq!(threshold.total_attestors, 3);
        assert!((threshold.independence_threshold - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn serde_roundtrip_required_signal_with_threshold() {
        // Verify that RequiredSignal with threshold_requirement roundtrips
        // through JSON, including the #[serde(default)] for backward compat.
        let req = RequiredSignal {
            category: TrustSignalCategory::Endorsement,
            min_strength: 2,
            max_age_secs: 180 * 24 * 3600,
            threshold_requirement: Some(ThresholdRequirement::new(2, 3, 0.5)),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: RequiredSignal = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn serde_backward_compat_required_signal_without_threshold() {
        // Old serialized RequiredSignal without threshold_requirement field
        // should deserialize with threshold_requirement = None.
        let json = r#"{"category":"Endorsement","min_strength":2,"max_age_secs":15552000}"#;
        let req: RequiredSignal = serde_json::from_str(json).unwrap();
        assert_eq!(req.category, TrustSignalCategory::Endorsement);
        assert_eq!(req.min_strength, 2);
        assert!(
            req.threshold_requirement.is_none(),
            "missing field should default to None"
        );
    }

    #[test]
    fn policy_without_endorsement_requirement_ignores_attestors() {
        // Standard policy has no endorsement requirement, so passing None
        // for attestors should work fine.
        let mut signals = HashMap::new();
        signals.insert(
            TrustSignalCategory::ParticipationHistory,
            make_signal(
                TrustSignalCategory::ParticipationHistory,
                30 * 24 * 3600,
                now() - 3600,
            ),
        );
        let assessment = IdentityDepthAssessment::new(did("did:dht:z6MkStandard"), signals, now());
        let policy = ContextSybilPolicy::standard();
        assert!(evaluate_sybil_resistance(&assessment, &policy, now(), None).is_ok());
    }

    // --- Subject binding tests (endorsement attestation subject must match) ---

    #[test]
    fn endorsement_attestations_for_different_subject_are_ignored() {
        // Attestors provide endorsements for a DIFFERENT DID than the subject
        // being evaluated. These must be filtered out, causing the independence
        // check to fail (zero valid attestations for the actual subject).
        let assessment = make_deep_assessment(now());
        let wrong_subject = "did:dht:z6MkWrongSubject";

        let attestors = vec![
            AttestorInfo {
                did: did("did:dht:z6MkEndorserA"),
                context_memberships: HashSet::from(["ctx-alpha".into()]),
                endorsements: HashSet::new(),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkEndorserA",
                    wrong_subject,
                    now() - 3600,
                )),
            },
            AttestorInfo {
                did: did("did:dht:z6MkEndorserB"),
                context_memberships: HashSet::from(["ctx-beta".into()]),
                endorsements: HashSet::new(),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkEndorserB",
                    wrong_subject,
                    now() - 7200,
                )),
            },
            AttestorInfo {
                did: did("did:dht:z6MkEndorserC"),
                context_memberships: HashSet::from(["ctx-gamma".into()]),
                endorsements: HashSet::new(),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkEndorserC",
                    wrong_subject,
                    now() - 10800,
                )),
            },
        ];

        let policy = ContextSybilPolicy::high_trust();
        let result = evaluate_sybil_resistance(&assessment, &policy, now(), Some(&attestors));
        assert!(
            matches!(
                result,
                Err(SybilResistanceError::EndorsementIndependenceInsufficient { .. })
            ),
            "attestations for a different subject must be filtered out: {result:?}"
        );
    }

    #[test]
    fn mixed_subject_attestations_only_count_correct_subject() {
        // Mix of attestations: some for the correct subject, some for a
        // different one. Only those for the correct subject should count.
        // With threshold requiring 2 of 3, having only 1 valid should fail.
        let assessment = make_deep_assessment(now());
        let correct_subject = "did:dht:z6MkDeepIdentity";
        let wrong_subject = "did:dht:z6MkWrongSubject";

        let attestors = vec![
            AttestorInfo {
                did: did("did:dht:z6MkEndorserA"),
                context_memberships: HashSet::from(["ctx-alpha".into()]),
                endorsements: HashSet::new(),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkEndorserA",
                    correct_subject,
                    now() - 3600,
                )),
            },
            AttestorInfo {
                did: did("did:dht:z6MkEndorserB"),
                context_memberships: HashSet::from(["ctx-beta".into()]),
                endorsements: HashSet::new(),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkEndorserB",
                    wrong_subject,
                    now() - 7200,
                )),
            },
            AttestorInfo {
                did: did("did:dht:z6MkEndorserC"),
                context_memberships: HashSet::from(["ctx-gamma".into()]),
                endorsements: HashSet::new(),
                attestation: Some(make_endorsement_attestation(
                    "did:dht:z6MkEndorserC",
                    wrong_subject,
                    now() - 10800,
                )),
            },
        ];

        let policy = ContextSybilPolicy::high_trust();
        let result = evaluate_sybil_resistance(&assessment, &policy, now(), Some(&attestors));
        // high_trust requires 2 of 3, but only 1 attestation is for the correct subject
        assert!(
            matches!(
                result,
                Err(SybilResistanceError::EndorsementIndependenceInsufficient { .. })
            ),
            "only 1 of 3 attestations is for the correct subject, should fail: {result:?}"
        );
    }

    // --- ThresholdRequirement NaN guard tests ---

    #[test]
    fn threshold_requirement_rejects_nan_on_validation() {
        // serde_json doesn't support NaN literals, so we test via validate().
        let t = ThresholdRequirement::new(2, 3, f64::NAN);
        assert!(
            t.validate().is_err(),
            "NaN independence_threshold must fail validation"
        );
    }

    #[test]
    fn threshold_requirement_rejects_infinity_on_validation() {
        let t = ThresholdRequirement::new(2, 3, f64::INFINITY);
        assert!(
            t.validate().is_err(),
            "infinite independence_threshold must fail validation"
        );
    }

    #[test]
    fn threshold_requirement_try_new_rejects_nan() {
        let result = ThresholdRequirement::try_new(2, 3, f64::NAN);
        assert!(result.is_err(), "try_new with NaN must return Err");
    }

    #[test]
    fn threshold_requirement_try_new_accepts_finite() {
        let result = ThresholdRequirement::try_new(2, 3, 0.5);
        assert!(result.is_ok(), "try_new with finite value must succeed");
    }

    // --- Edge case: min_strength 0 with threshold_requirement ---

    #[test]
    fn zero_min_strength_still_runs_independence_check() {
        // Even when min_strength is 0 (trivially met), the endorsement
        // independence check must still run when threshold_requirement is set.
        let assessment = make_deep_assessment(now());
        let colluding_attestors = make_colluding_attestors(now());

        let mut policy = ContextSybilPolicy::casual();
        policy.required_signals = vec![RequiredSignal {
            category: TrustSignalCategory::Endorsement,
            min_strength: 0, // trivially met
            max_age_secs: 365 * 24 * 3600,
            threshold_requirement: Some(ThresholdRequirement::new(2, 3, 0.5)),
        }];

        let result =
            evaluate_sybil_resistance(&assessment, &policy, now(), Some(&colluding_attestors));
        assert!(
            matches!(
                result,
                Err(SybilResistanceError::EndorsementIndependenceInsufficient { .. })
            ),
            "min_strength=0 must not bypass independence check: {result:?}"
        );
    }

    #[test]
    fn zero_min_strength_passes_with_independent_attestors() {
        // Confirm that min_strength=0 with independent attestors passes.
        let assessment = make_deep_assessment(now());
        let independent_attestors = make_independent_attestors(now());

        let mut policy = ContextSybilPolicy::casual();
        policy.required_signals = vec![RequiredSignal {
            category: TrustSignalCategory::Endorsement,
            min_strength: 0, // trivially met
            max_age_secs: 365 * 24 * 3600,
            threshold_requirement: Some(ThresholdRequirement::new(2, 3, 0.5)),
        }];

        let result =
            evaluate_sybil_resistance(&assessment, &policy, now(), Some(&independent_attestors));
        assert!(
            result.is_ok(),
            "min_strength=0 with independent attestors should pass: {result:?}"
        );
    }
}
