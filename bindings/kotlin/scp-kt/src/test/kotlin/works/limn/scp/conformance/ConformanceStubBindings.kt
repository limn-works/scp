// ConformanceStubBindings.kt — Configurable stub bindings for conformance tests (SCP-120)
// Provenance: SCP-120, ADR-028

package works.limn.scp.conformance

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import works.limn.scp.bridge.BridgeException
import works.limn.scp.bridge.CancellationHandle
import works.limn.scp.bridge.MessageCallback
import works.limn.scp.bridge.NativeBindings

/**
 * Stub [NativeBindings] for conformance tests that exercises every SDK
 * operation path.
 *
 * Each method either returns a configurable result or throws a
 * [BridgeException] with a configurable error code. This allows
 * conformance tests to verify both success and error paths for every
 * operation in the cross-platform test suite.
 *
 * Default behavior: all operations return plausible stub values
 * matching the cross-platform fixture expectations.
 */
@Suppress("TooManyFunctions")
class ConformanceStubBindings : NativeBindings {
    var identityCreateResult: Long = 1L
    var identityCreateError: BridgeException? = null
    var identityCreateCustody: String? = null

    var identityLoadResult: Long = 2L
    var identityLoadError: BridgeException? = null
    var identityLoadDid: String? = null

    var identityResolveResult: String = """{"did":"did:dht:stub"}"""
    var identityResolveError: BridgeException? = null

    var contextCreateResult: Long = 10L
    var contextCreateError: BridgeException? = null
    var contextJoinError: BridgeException? = null

    var contextLeaveCalled = false
    var contextLeaveError: BridgeException? = null
    var contextCloseCalled = false
    var contextCloseError: BridgeException? = null
    var contextSendCalled = false
    var contextSendError: BridgeException? = null
    var contextSendPayload: ByteArray? = null

    var contextSubscribeResult: Long = 100L
    var lastMessageCallback: MessageCallback? = null

    var outletRegisterResult: String = "outlet-001"
    var outletRegisterError: BridgeException? = null
    var outletInvokeResult: String = """{"output":"ok"}"""
    var outletInvokeError: BridgeException? = null
    var outletVerifyResult: String = """{"outlet_id":"stub","passed":true,"failures":[]}"""
    var outletVerifyError: BridgeException? = null
    var outletInvokeCrossContextResult: String = """{"cross_context":"ok"}"""
    var outletInvokeCrossContextError: BridgeException? = null
    var outletInvokeCrossContextSagaResult: String = """{"saga_id":"saga-001"}"""
    var outletInvokeCrossContextSagaError: BridgeException? = null
    var lastSagaArgs: List<String>? = null
    var outletSessionCreateResult: String = "session-001"
    var outletSessionCreateError: BridgeException? = null
    var outletSessionInvokeResult: String = """{"session":"ok"}"""
    var outletSessionInvokeError: BridgeException? = null
    var outletSessionCloseError: BridgeException? = null

    var ucanValidateError: BridgeException? = null
    var ucanMintResult: String = "minted-token"
    var ucanMintError: BridgeException? = null
    var ucanRevokeError: BridgeException? = null
    var ucanDelegateResult: String = "delegated-token"
    var ucanDelegateError: BridgeException? = null

    var eventLogQueryResult: String = """[{"event":"joined"}]"""
    var eventLogQueryError: BridgeException? = null
    var eventLogVerifyResult: Boolean = true
    var eventLogVerifyError: BridgeException? = null

    var eventLogCheckpointResult: String =
        """{"context_id":"ctx-1","sender_did":"did:dht:stub",""" +
            """"event_count":10,"merkle_root":"abcdef","epoch":5,""" +
            """"timestamp":1710000000,"signature":"c2lnbmVk"}"""
    var eventLogCheckpointError: BridgeException? = null

    var transportConnectResult: Long = 99L
    var transportConnectError: BridgeException? = null
    var transportStatusResult: String = """{"connected":true}"""
    var transportStatusError: BridgeException? = null
    var transportDisconnectCalled = false
    var transportDisconnectError: BridgeException? = null

    override fun identityCreate(custody: String): Long {
        identityCreateCustody = custody
        identityCreateError?.let { throw it }
        return identityCreateResult
    }

    override fun identityLoad(did: String): Long {
        identityLoadDid = did
        identityLoadError?.let { throw it }
        return identityLoadResult
    }

    override fun identityResolve(did: String): String {
        identityResolveError?.let { throw it }
        return identityResolveResult
    }

    override fun contextCreate(
        identityHandle: Long,
        paramsJson: String,
        consequenceRulesJson: String?,
        consequenceConfigJson: String?,
    ): Long {
        contextCreateError?.let { throw it }
        return contextCreateResult
    }

    override fun contextJoin(
        contextHandle: Long,
        identityHandle: Long,
        spendingUcanJwt: String?,
    ) {
        contextJoinError?.let { throw it }
    }

    override fun contextLeave(
        contextHandle: Long,
        identityHandle: Long,
    ) {
        contextLeaveCalled = true
        contextLeaveError?.let { throw it }
    }

    override fun contextClose(
        contextHandle: Long,
        identityHandle: Long,
    ) {
        contextCloseCalled = true
        contextCloseError?.let { throw it }
    }

    override fun contextSend(
        contextHandle: Long,
        identityHandle: Long,
        payload: ByteArray,
        spendingUcanJwt: String?,
    ) {
        contextSendCalled = true
        contextSendPayload = payload
        contextSendError?.let { throw it }
    }

    override fun contextSubscribe(
        contextHandle: Long,
        callback: MessageCallback,
    ): Long {
        lastMessageCallback = callback
        return contextSubscribeResult
    }

    override fun contextUnsubscribe(subscriptionHandle: Long) = Unit

    override fun contextSetEconomicPolicy(
        contextHandle: Long,
        policyJson: String,
    ) = Unit

    override fun contextGetEconomicPolicy(contextHandle: Long): String? = null

    // MembershipBindings
    override fun contextMemberCount(contextHandle: Long): Long? = 1L

    override fun contextIsMember(
        contextHandle: Long,
        did: String,
    ): Boolean = true

    override fun contextMemberDids(contextHandle: Long): List<String> = listOf("did:dht:stub")

    override fun contextMemberRole(
        contextHandle: Long,
        did: String,
    ): String? = "admin"

    // GovernanceBindings
    override fun governanceExecute(
        contextHandle: Long,
        proposalIdHex: String,
    ): String = """{"status":"executed"}"""

    override fun governancePropose(
        contextHandle: Long,
        proposerDid: String,
        actionJson: String,
    ): String = """{"proposal_id":"0000","status":"Pending","execution_result":null}"""

    override fun governanceApprove(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String = """{"status":"Pending"}"""

    override fun governanceReject(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String = """{"status":"Pending"}"""

    override fun governanceWithdraw(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String = """{"status":"Pending"}"""

    override fun governanceGetProposal(
        contextHandle: Long,
        proposalIdHex: String,
    ): String = """{"proposal_id":"0000","status":"Pending","action":"{}","proposer_did":"did:dht:stub","votes":{}}"""

    override fun governanceListProposals(contextHandle: Long): String = "[]"

    override fun applyPendingCeilingModification(
        contextHandle: Long,
        currentTimestamp: Long,
    ): Boolean = false

    override fun finalizeClose(contextHandle: Long) = Unit

    @Suppress("LongParameterList")
    override fun createGovernanceCheckpoint(
        contextHandle: Long,
        checkpointSeq: Long,
        merkleRootHex: String,
        eventCount: Long,
        lastEventHashHex: String,
        stateSnapshotHashHex: String,
        creatorDid: String,
        creatorSignatureHex: String,
    ): String = "{}"

    override fun addCheckpointCosignature(
        contextHandle: Long,
        checkpointJson: String,
        signerDid: String,
        signatureHex: String,
    ): String = "{}"

    override fun restoreContext(contextId: String) = Unit

    override fun restoreAllContexts(): String = "[]"

    // BroadcastBindings
    override fun broadcastSubscribe(
        contextHandle: Long,
        subscriberDid: String,
    ) = Unit

    override fun broadcastUnsubscribe(
        contextHandle: Long,
        subscriberDid: String,
        rotateKeys: Boolean,
    ) = Unit

    override fun broadcastPublish(
        contextHandle: Long,
        identityHandle: Long,
        payload: ByteArray,
    ) = Unit

    override fun broadcastBlockSubscriber(
        contextHandle: Long,
        subscriberDid: String,
        blockerDid: String,
    ) = Unit

    override fun broadcastUnblockSubscriber(
        contextHandle: Long,
        subscriberDid: String,
        unblockerDid: String,
    ) = Unit

    override fun broadcastHandleKeyRequest(
        contextHandle: Long,
        authorDid: String,
        requesterDid: String,
        wrappingPubkey: ByteArray,
    ): String? = """{"key":"stub"}"""

    override fun broadcastSubscriberCount(contextHandle: Long): Long? = 0L

    override fun broadcastIsSubscriber(
        contextHandle: Long,
        did: String,
    ): Boolean = false

    override fun broadcastAdmission(contextHandle: Long): String? = "Open"

    override fun broadcastPublishAsset(
        contextHandle: Long,
        identityHandle: Long,
        assetJson: String,
        deployId: String?,
    ): String = """{"blob_id":"stub-blob","etag":"stub-etag","deploy_id":"stub-deploy"}"""

    override fun broadcastPublishAssets(
        contextHandle: Long,
        identityHandle: Long,
        assetsJson: String,
        deployId: String?,
    ): String = """{"results":[{"blob_id":"stub-blob",""" +
        """"etag":"stub-etag","deploy_id":"stub-deploy"}],""" +
        """"deploy_id":"stub-deploy"}"""

    override fun outletRegister(
        contextHandle: Long,
        definitionJson: String,
    ): String {
        outletRegisterError?.let { throw it }
        return outletRegisterResult
    }

    @Suppress("LongParameterList")
    override fun outletInvoke(
        contextHandle: Long,
        outletId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String?,
        proofTokens: List<String>?,
        spendingUcan: String?,
    ): String {
        outletInvokeError?.let { throw it }
        return outletInvokeResult
    }

    override fun outletVerify(
        contextHandle: Long,
        outletId: String,
    ): String {
        outletVerifyError?.let { throw it }
        return outletVerifyResult
    }

    override fun outletInterfaceExpose(
        contextHandle: Long,
        outletId: String,
        targetContextId: String,
        rateLimitJson: String?,
    ): String =
        Json.encodeToString(
            buildJsonObject {
                put("source_context", "ctx-src")
                put("target_context", targetContextId)
                put("outlet_id", outletId)
                put("approved_by_source", true)
                put("approved_by_target", false)
            },
        )

    override fun outletInterfaceAccept(
        contextHandle: Long,
        interfaceJson: String,
    ): String = interfaceJson.replace("\"approved_by_target\":false", "\"approved_by_target\":true")

    override fun outletInterfaceRevoke(
        contextHandle: Long,
        interfaceIdHex: String,
    ): String =
        Json.encodeToString(
            buildJsonObject {
                put("interface_id", interfaceIdHex)
                put("revoking_context", "ctx-revoker")
                put("revoked_at", 1700000000000)
            },
        )

    @Suppress("LongParameterList")
    override fun outletInvokeCrossContext(
        sourceContextHandle: Long,
        targetContextHandle: Long,
        outletId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String,
        chainDepth: Int,
        proofTokens: List<String>?,
    ): String {
        outletInvokeCrossContextError?.let { throw it }
        return outletInvokeCrossContextResult
    }

    @Suppress("LongParameterList")
    override fun outletInvokeCrossContextSaga(
        sourceContextHandle: Long,
        targetContextHandle: Long,
        callerDid: String,
        outletRegistrationId: String,
        inputJson: String,
        assertedNonceHex: String,
        timestampMs: Long,
        chainDepth: Int,
        ucanProofId: String?,
    ): String {
        lastSagaArgs =
            listOf(
                sourceContextHandle.toString(),
                targetContextHandle.toString(),
                callerDid,
                outletRegistrationId,
                inputJson,
                assertedNonceHex,
                timestampMs.toString(),
                chainDepth.toString(),
                ucanProofId.toString(),
            )
        outletInvokeCrossContextSagaError?.let { throw it }
        return outletInvokeCrossContextSagaResult
    }

    override fun outletSessionCreate(
        contextHandle: Long,
        outletId: String,
        sourceContextId: String,
        ttlSeconds: Long?,
    ): String {
        outletSessionCreateError?.let { throw it }
        return outletSessionCreateResult
    }

    @Suppress("LongParameterList")
    override fun outletSessionInvoke(
        contextHandle: Long,
        sessionId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String,
        proofTokens: List<String>?,
    ): String {
        outletSessionInvokeError?.let { throw it }
        return outletSessionInvokeResult
    }

    override fun outletSessionClose(
        contextHandle: Long,
        sessionId: String,
    ) {
        outletSessionCloseError?.let { throw it }
    }

    override fun ucanValidate(
        contextHandle: Long,
        token: String,
        capability: String,
        presentingAgentDid: String,
        proofTokens: List<String>?,
    ) {
        ucanValidateError?.let { throw it }
    }

    override fun ucanMint(
        contextHandle: Long,
        memberDid: String,
        capabilitiesJson: String,
    ): String {
        ucanMintError?.let { throw it }
        return ucanMintResult
    }

    override fun ucanRevoke(
        contextHandle: Long,
        token: String,
        revokerDid: String,
    ) {
        ucanRevokeError?.let { throw it }
    }

    override fun ucanDelegate(
        contextHandle: Long,
        delegatorDid: String,
        delegateeDid: String,
        parentToken: String,
        capabilitiesJson: String,
    ): String {
        ucanDelegateError?.let { throw it }
        return ucanDelegateResult
    }

    override fun eventLogQuery(
        contextHandle: Long,
        filterJson: String,
    ): String {
        eventLogQueryError?.let { throw it }
        return eventLogQueryResult
    }

    override fun eventLogVerify(
        contextHandle: Long,
        claimJson: String,
    ): Boolean {
        eventLogVerifyError?.let { throw it }
        return eventLogVerifyResult
    }

    override fun eventLogCheckpoint(
        contextHandle: Long,
        identityHandle: Long,
        epoch: Long,
    ): String {
        eventLogCheckpointError?.let { throw it }
        return eventLogCheckpointResult
    }

    override fun transportConnect(
        configJson: String,
        cancellationHandle: CancellationHandle?,
    ): Long {
        transportConnectError?.let { throw it }
        return transportConnectResult
    }

    override fun transportStatus(transportHandle: Long): String {
        transportStatusError?.let { throw it }
        return transportStatusResult
    }

    override fun transportDisconnect(transportHandle: Long) {
        transportDisconnectCalled = true
        transportDisconnectError?.let { throw it }
    }

    fun reset() {
        identityCreateResult = 1L
        identityCreateError = null
        identityCreateCustody = null
        identityLoadResult = 2L
        identityLoadError = null
        identityLoadDid = null
        identityResolveResult = """{"did":"did:dht:stub"}"""
        identityResolveError = null
        contextCreateResult = 10L
        contextCreateError = null
        contextJoinError = null
        contextLeaveCalled = false
        contextLeaveError = null
        contextCloseCalled = false
        contextCloseError = null
        contextSendCalled = false
        contextSendError = null
        contextSendPayload = null
        contextSubscribeResult = 100L
        lastMessageCallback = null
        outletRegisterResult = "outlet-001"
        outletRegisterError = null
        outletInvokeResult = """{"output":"ok"}"""
        outletInvokeError = null
        outletVerifyResult = """{"outlet_id":"stub","passed":true,"failures":[]}"""
        outletVerifyError = null
        outletInvokeCrossContextResult = """{"cross_context":"ok"}"""
        outletInvokeCrossContextError = null
        outletInvokeCrossContextSagaResult = """{"saga_id":"saga-001"}"""
        outletInvokeCrossContextSagaError = null
        lastSagaArgs = null
        outletSessionCreateResult = "session-001"
        outletSessionCreateError = null
        outletSessionInvokeResult = """{"session":"ok"}"""
        outletSessionInvokeError = null
        outletSessionCloseError = null
        ucanValidateError = null
        ucanMintResult = "minted-token"
        ucanMintError = null
        ucanRevokeError = null
        ucanDelegateResult = "delegated-token"
        ucanDelegateError = null
        eventLogQueryResult = """[{"event":"joined"}]"""
        eventLogQueryError = null
        eventLogVerifyResult = true
        eventLogVerifyError = null
        eventLogCheckpointResult =
            """{"context_id":"ctx-1","sender_did":"did:dht:stub",""" +
            """"event_count":10,"merkle_root":"abcdef","epoch":5,""" +
            """"timestamp":1710000000,"signature":"c2lnbmVk"}"""
        eventLogCheckpointError = null
        transportConnectResult = 99L
        transportConnectError = null
        transportStatusResult = """{"connected":true}"""
        transportStatusError = null
        transportDisconnectCalled = false
        transportDisconnectError = null
    }
}
