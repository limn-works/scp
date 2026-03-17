// Trust.kt — Kotlin SDK trust aggregation wrapper (#596)
//
// Wraps the trust aggregation UniFFI bridge function as a suspend function
// with proper dispatcher assignment per ADR-028. Trust aggregation combines
// all four trust engine layers into a single TrustInput for agent-level
// evaluation.
//
// Provenance: §7.3 (Trust Aggregation), ADR-017

@file:Suppress("MatchingDeclarationName")

package works.limn.scp

import works.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for trust aggregation operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
interface TrustBindings {
    /**
     * Aggregates all trust engine layers into a single TrustInput.
     *
     * @param contextId The context to aggregate trust inputs for.
     * @param subjectDid The DID of the subject to evaluate.
     * @param eventsJson JSON array of event log entries.
     * @param merkleRootJson JSON array of 32 bytes (Merkle root).
     * @param consequenceRulesJson JSON array of consequence rules.
     * @param thresholdRequirementsJson JSON object of threshold requirements.
     * @param attestorSetsJson JSON object of attestor sets.
     * @param cachedAttestationsJson JSON array of cached attestations.
     * @param challengeResultsJson JSON array of challenge results.
     * @return JSON string containing the serialized TrustInput.
     * @throws BridgeException if inputs are malformed or aggregation fails.
     */
    @Suppress("LongParameterList")
    fun aggregateTrustInput(
        contextId: String,
        subjectDid: String,
        eventsJson: String,
        merkleRootJson: String,
        consequenceRulesJson: String,
        thresholdRequirementsJson: String,
        attestorSetsJson: String,
        cachedAttestationsJson: String,
        challengeResultsJson: String,
    ): String
}

/**
 * Aggregates all trust engine layers into a single TrustInput.
 *
 * Combines participation records, attestation verification, challenge
 * results, consequence structure, and threshold counts. Returns the
 * aggregated result as a JSON string.
 *
 * @param bridge The coroutine bridge with trust bindings.
 * @param contextId The context to aggregate trust inputs for.
 * @param subjectDid The DID of the subject to evaluate.
 * @param eventsJson JSON array of event log entries.
 * @param merkleRootJson JSON array of 32 bytes (Merkle root).
 * @param consequenceRulesJson JSON array of consequence rules.
 * @param thresholdRequirementsJson JSON object of threshold requirements.
 * @param attestorSetsJson JSON object of attestor sets.
 * @param cachedAttestationsJson JSON array of cached attestations.
 * @param challengeResultsJson JSON array of challenge results.
 * @return JSON string containing the serialized TrustInput.
 * @throws BridgeException if inputs are malformed or aggregation fails.
 * @throws IllegalStateException if trust bindings are not configured.
 */
@Suppress("LongParameterList")
suspend fun aggregateTrustInput(
    bridge: CoroutineBridge,
    contextId: String,
    subjectDid: String,
    eventsJson: String,
    merkleRootJson: String,
    consequenceRulesJson: String = "[]",
    thresholdRequirementsJson: String = "{}",
    attestorSetsJson: String = "{}",
    cachedAttestationsJson: String = "[]",
    challengeResultsJson: String = "[]",
): String {
    val trustBindings =
        bridge.extended.trust
            ?: error("Trust bindings not configured — provide TrustBindings in ExtendedBindings")
    return bridge.ffiCall {
        trustBindings.aggregateTrustInput(
            contextId,
            subjectDid,
            eventsJson,
            merkleRootJson,
            consequenceRulesJson,
            thresholdRequirementsJson,
            attestorSetsJson,
            cachedAttestationsJson,
            challengeResultsJson,
        )
    }
}
