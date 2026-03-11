// Participation.kt — Kotlin SDK participation types and verification (#426, SCP-RG-017)
//
// Pure Kotlin data classes and verification logic for participation-based
// admission (SCP-BA-004). These types mirror the Rust trust module's
// participation types and can be serialized to JSON for FFI calls.
//
// Provenance: §9.3 (Sybil Resistance), §7.3.2.1, ADR-017, SCP-BA-004

package works.limn.scp

/**
 * A single participation fact about a participant in a context.
 *
 * Facts represent measurable participation data: message counts, governance
 * actions, time spent, etc. The [factType] discriminator determines the
 * semantics of [value].
 *
 * @property factType Type discriminator (e.g., "message_count",
 *   "governance_action_count", "membership_duration_secs").
 * @property participantDid DID of the participant this fact describes.
 * @property contextId Context where the participation occurred.
 * @property value Numeric value of the fact.
 */
data class ParticipationFact(
    val factType: String,
    val participantDid: String,
    val contextId: String,
    val value: Long,
)

/**
 * A threshold requirement for a specific participation fact type.
 *
 * Defines the minimum (and optional maximum) value a participant must
 * have for a given [factType] to satisfy an admission requirement.
 *
 * @property factType The fact type this threshold applies to (must match
 *   [ParticipationFact.factType]).
 * @property minimum Minimum value required (inclusive).
 * @property maximum Optional maximum value allowed (inclusive). Null means
 *   no upper bound.
 */
data class ParticipationThreshold(
    val factType: String,
    val minimum: Long,
    val maximum: Long? = null,
)

/**
 * A participant's aggregated participation profile.
 *
 * Collects all [ParticipationFact] entries for a single participant,
 * grouped for verification against [RequireParticipation] requirements.
 *
 * @property participantDid DID of the participant.
 * @property facts List of participation facts for this participant.
 */
data class ParticipationProfile(
    val participantDid: String,
    val facts: List<ParticipationFact>,
)

/**
 * A participation admission requirement.
 *
 * Specifies a set of [thresholds] that must be satisfied for admission.
 * When [requireAll] is true, ALL thresholds must be met. When false,
 * ANY single threshold is sufficient.
 *
 * @property thresholds List of threshold requirements to check.
 * @property requireAll If true, all thresholds must be met (AND logic).
 *   If false, any threshold is sufficient (OR logic).
 */
data class RequireParticipation(
    val thresholds: List<ParticipationThreshold>,
    val requireAll: Boolean = true,
)

/**
 * Verifies a participant's profile against participation requirements.
 *
 * Pure Kotlin implementation matching the Rust trust module's
 * `verify_participation_requirements` logic. Checks each threshold in the
 * requirement against matching facts in the profile.
 *
 * @param requirement The participation requirement to verify against.
 * @param profile The participant's profile containing their facts.
 * @return true if the profile satisfies the requirement, false otherwise.
 */
fun verifyParticipationRequirements(
    requirement: RequireParticipation,
    profile: ParticipationProfile,
): Boolean {
    if (requirement.thresholds.isEmpty()) return true

    val results =
        requirement.thresholds.map { threshold ->
            checkThreshold(threshold, profile.facts)
        }

    return if (requirement.requireAll) {
        results.all { it }
    } else {
        results.any { it }
    }
}

/**
 * Checks a single threshold against a list of facts.
 *
 * Finds facts matching the threshold's [ParticipationThreshold.factType]
 * and sums their values. The sum must meet the minimum and (if specified)
 * not exceed the maximum.
 */
private fun checkThreshold(
    threshold: ParticipationThreshold,
    facts: List<ParticipationFact>,
): Boolean {
    val total =
        facts
            .filter { it.factType == threshold.factType }
            .sumOf { it.value }

    if (total < threshold.minimum) return false
    if (threshold.maximum != null && total > threshold.maximum) return false
    return true
}
