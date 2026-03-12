// ConformanceStubBindings.kt — Configurable stub bindings for conformance tests (SCP-120)
// Provenance: SCP-120, ADR-028

package works.limn.scp.conformance

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
    var contextJoinResult: Long = 11L
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

    var toolRegisterResult: String = "tool-001"
    var toolRegisterError: BridgeException? = null
    var toolInvokeResult: String = """{"output":"ok"}"""
    var toolInvokeError: BridgeException? = null
    var toolVerifyResult: Boolean = true
    var toolVerifyError: BridgeException? = null

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
    @Suppress("MaxLineLength")
    var eventLogCheckpointResult: String =
        """{"context_id":"ctx-1","sender_did":"did:dht:stub","event_count":10,"merkle_root":"abcdef","epoch":5}"""
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
    ): Long {
        contextCreateError?.let { throw it }
        return contextCreateResult
    }

    override fun contextJoin(
        identityHandle: Long,
        contextId: String,
    ): Long {
        contextJoinError?.let { throw it }
        return contextJoinResult
    }

    override fun contextLeave(contextHandle: Long) {
        contextLeaveCalled = true
        contextLeaveError?.let { throw it }
    }

    override fun contextClose(contextHandle: Long) {
        contextCloseCalled = true
        contextCloseError?.let { throw it }
    }

    override fun contextSend(contextHandle: Long, payload: ByteArray) {
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
    override fun contextSetEconomicPolicy(contextHandle: Long, policyJson: String) = Unit
    override fun contextGetEconomicPolicy(contextHandle: Long): String? = null

    // MembershipBindings
    override fun contextMemberCount(contextHandle: Long): Long? = 1L
    override fun contextIsMember(contextHandle: Long, did: String): Boolean = true
    override fun contextMemberDids(contextHandle: Long): List<String> = listOf("did:dht:stub")
    override fun contextMemberRole(contextHandle: Long, did: String): String? = "admin"

    // GovernanceBindings
    override fun governanceExecute(contextHandle: Long, proposalJson: String): String =
        """{"status":"executed"}"""
    override fun governancePropose(contextHandle: Long, proposerDid: String, actionJson: String): String =
        """{"proposal_id":"0000","status":"Pending","execution_result":null}"""
    override fun governanceApprove(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""
    override fun governanceReject(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""
    override fun governanceWithdraw(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""
    override fun governanceGetProposal(contextHandle: Long, proposalIdHex: String): String =
        """{"proposal_id":"0000","status":"Pending","action":"{}","proposer_did":"did:dht:stub","votes":{}}"""
    override fun governanceListProposals(contextHandle: Long): String = "[]"

    // BroadcastBindings
    override fun broadcastSubscribe(contextHandle: Long, subscriberDid: String) = Unit
    override fun broadcastUnsubscribe(contextHandle: Long, subscriberDid: String, rotateKeys: Boolean) = Unit
    override fun broadcastPublish(contextHandle: Long, authorDid: String, payload: ByteArray) = Unit
    override fun broadcastBlockSubscriber(contextHandle: Long, subscriberDid: String, blockerDid: String) = Unit
    override fun broadcastUnblockSubscriber(contextHandle: Long, subscriberDid: String, unblockerDid: String) = Unit
    override fun broadcastHandleKeyRequest(contextHandle: Long, authorDid: String, requesterDid: String): String =
        """{"key":"stub"}"""
    override fun broadcastSubscriberCount(contextHandle: Long): Long? = 0L
    override fun broadcastIsSubscriber(contextHandle: Long, did: String): Boolean = false
    override fun broadcastAdmission(contextHandle: Long): String? = "Open"

    override fun toolRegister(
        contextHandle: Long,
        definitionJson: String,
    ): String {
        toolRegisterError?.let { throw it }
        return toolRegisterResult
    }

    override fun toolInvoke(
        contextHandle: Long,
        toolId: String,
        inputJson: String,
    ): String {
        toolInvokeError?.let { throw it }
        return toolInvokeResult
    }

    override fun toolVerify(
        toolId: String,
        inputJson: String,
        outputJson: String,
    ): Boolean {
        toolVerifyError?.let { throw it }
        return toolVerifyResult
    }

    override fun ucanValidate(
        token: String,
        capability: String,
        contextId: String,
    ) {
        ucanValidateError?.let { throw it }
    }

    override fun ucanMint(
        identityHandle: Long,
        memberDid: String,
        capabilitiesJson: String,
    ): String {
        ucanMintError?.let { throw it }
        return ucanMintResult
    }

    override fun ucanRevoke(
        identityHandle: Long,
        token: String,
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
        contextId: String,
        filterJson: String,
    ): String {
        eventLogQueryError?.let { throw it }
        return eventLogQueryResult
    }

    override fun eventLogVerify(
        contextId: String,
        proofJson: String,
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
        contextJoinResult = 11L
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
        toolRegisterResult = "tool-001"
        toolRegisterError = null
        toolInvokeResult = """{"output":"ok"}"""
        toolInvokeError = null
        toolVerifyResult = true
        toolVerifyError = null
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
        @Suppress("MaxLineLength")
        eventLogCheckpointResult =
            """{"context_id":"ctx-1","sender_did":"did:dht:stub","event_count":10,"merkle_root":"abcdef","epoch":5}"""
        eventLogCheckpointError = null
        transportConnectResult = 99L
        transportConnectError = null
        transportStatusResult = """{"connected":true}"""
        transportStatusError = null
        transportDisconnectCalled = false
        transportDisconnectError = null
    }
}
