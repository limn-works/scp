// Invitation.kt — Kotlin SDK invitation evaluation wrapper (#614)
//
// Wraps the UniFFI `evaluate_invitation` bridge function as a suspend
// function with proper dispatcher assignment per ADR-028.
//
// Provenance: §5.7 (Context Invitation), `.docs/standards/sdk-common.md`

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Result of evaluating a context invitation through the pipeline.
 *
 * @property decision The pipeline decision: `"auto_accept"` or `"prompt_agent"`.
 */
data class InvitationEvaluationResult(val decision: String) {
    /** Whether the invitation was auto-accepted. */
    val isAutoAccept: Boolean get() = decision == "auto_accept"
}

/**
 * Evaluates a context invitation through the sequential pipeline.
 *
 * Runs the 4-step evaluation pipeline:
 * 1. **Template check** — validates params match the claimed template.
 * 2. **Economic policy check** — verifies spending capability for paid contexts.
 * 3. **Auto-accept check** — evaluates trust, TTL cap, and rate limit.
 * 4. **Agent prompt** — falls through if no auto-accept matches.
 *
 * @param paramsJson JSON-serialized `ContextParams` from the invitation.
 * @param inviterDid DID string of the identity sending the invitation.
 * @param identityDid DID string of the local identity receiving the invitation.
 * @param policyJson Optional JSON-serialized `AutoAcceptPolicy`.
 * @param spendingJson Optional JSON-serialized `SpendingContext`.
 * @param trustedDids List of trusted DID strings for trust requirement evaluation.
 * @return An [InvitationEvaluationResult] with the pipeline decision.
 * @throws works.limn.scp.bridge.BridgeException if evaluation fails.
 */
suspend fun evaluateContextInvitation(
    paramsJson: String,
    inviterDid: String,
    identityDid: String,
    policyJson: String? = null,
    spendingJson: String? = null,
    trustedDids: List<String> = emptyList(),
): InvitationEvaluationResult = withContext(Dispatchers.IO) {
    @Suppress("TooGenericExceptionCaught")
    try {
        val decision = evaluateInvitation(
            paramsJson = paramsJson,
            inviterDid = inviterDid,
            identityDid = identityDid,
            policyJson = policyJson,
            spendingJson = spendingJson,
            trustedDids = trustedDids,
        )
        InvitationEvaluationResult(decision)
    } catch (e: Exception) {
        throw works.limn.scp.bridge.BridgeException(
            message = e.message ?: "invitation evaluation failed",
            code = "SCP-CTX-2060",
        )
    }
}
