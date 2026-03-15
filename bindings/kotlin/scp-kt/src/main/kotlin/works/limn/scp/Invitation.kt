// Invitation.kt — Kotlin SDK invitation evaluation wrapper (#614)
//
// Wraps the UniFFI `evaluate_invitation` bridge function as a suspend
// function with proper dispatcher assignment per ADR-028.
//
// Provenance: §5.7 (Context Invitation), `.docs/standards/sdk-common.md`

@file:Suppress("MatchingDeclarationName")

package works.limn.scp

import works.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for invitation evaluation operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
interface InvitationBindings {
    /**
     * Evaluates a context invitation through the sequential pipeline.
     *
     * @param paramsJson JSON-serialized `ContextParams` from the invitation.
     * @param inviterDid DID string of the identity sending the invitation.
     * @param identityDid DID string of the local identity receiving the invitation.
     * @param policyJson Optional JSON-serialized `AutoAcceptPolicy`.
     * @param spendingJson Optional JSON-serialized `SpendingContext`.
     * @param trustedDids List of trusted DID strings for trust requirement evaluation.
     * @return Pipeline decision string: `"auto_accept"` or `"prompt_agent"`.
     * @throws BridgeException if evaluation fails.
     */
    @Suppress("LongParameterList")
    fun evaluateInvitation(
        paramsJson: String,
        inviterDid: String,
        identityDid: String,
        policyJson: String?,
        spendingJson: String?,
        trustedDids: List<String>,
    ): String
}

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
 * @param bridge The coroutine bridge with invitation bindings.
 * @param paramsJson JSON-serialized `ContextParams` from the invitation.
 * @param inviterDid DID string of the identity sending the invitation.
 * @param identityDid DID string of the local identity receiving the invitation.
 * @param policyJson Optional JSON-serialized `AutoAcceptPolicy`.
 * @param spendingJson Optional JSON-serialized `SpendingContext`.
 * @param trustedDids List of trusted DID strings for trust requirement evaluation.
 * @return An [InvitationEvaluationResult] with the pipeline decision.
 * @throws works.limn.scp.bridge.BridgeException if evaluation fails.
 * @throws IllegalStateException if invitation bindings are not configured.
 */
@Suppress("LongParameterList")
suspend fun evaluateContextInvitation(
    bridge: CoroutineBridge,
    paramsJson: String,
    inviterDid: String,
    identityDid: String,
    policyJson: String? = null,
    spendingJson: String? = null,
    trustedDids: List<String> = emptyList(),
): InvitationEvaluationResult {
    val invitationBindings = bridge.extended.invitation
        ?: error("Invitation bindings not configured — provide InvitationBindings in ExtendedBindings")
    return bridge.ffiCall {
        val decision = invitationBindings.evaluateInvitation(
            paramsJson = paramsJson,
            inviterDid = inviterDid,
            identityDid = identityDid,
            policyJson = policyJson,
            spendingJson = spendingJson,
            trustedDids = trustedDids,
        )
        InvitationEvaluationResult(decision)
    }
}
