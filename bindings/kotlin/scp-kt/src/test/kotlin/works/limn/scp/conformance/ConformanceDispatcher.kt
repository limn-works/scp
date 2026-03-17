// ConformanceDispatcher.kt — Operation dispatcher for cross-platform conformance tests (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Conformance Testing"

package works.limn.scp.conformance

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import works.limn.scp.bridge.BridgeException
import works.limn.scp.bridge.CoroutineBridge

/**
 * Maps conformance operation strings to Kotlin SDK bridge calls.
 *
 * This dispatcher is the Kotlin equivalent of the Swift conformance
 * test runner's `dispatch(operation:input:)` method. It translates
 * fixture operation strings (e.g., "identity_create") into actual
 * SDK bridge method invocations and returns result dictionaries for
 * comparison against fixture `expected` values.
 *
 * Since UniFFI-generated bindings do not exist yet, the dispatcher
 * operates against [ConformanceStubBindings], which returns configured
 * stub data or throws [BridgeException] with documented error codes.
 *
 * @param bridge The coroutine bridge backed by stub bindings.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ConformanceDispatcher(
    private val bridge: CoroutineBridge,
) {
    @Suppress("CyclomaticComplexMethod")
    suspend fun dispatch(
        operation: String,
        input: Map<String, String>,
    ): Map<String, String> =
        when (operation) {
            "identity_create" -> dispatchIdentityCreate(input)
            "identity_load" -> dispatchIdentityLoad(input)
            "identity_resolve" -> dispatchIdentityResolve(input)
            "context_create" -> dispatchContextCreate(input)
            "context_join" -> dispatchContextJoin(input)
            "context_leave" -> dispatchContextLeave(input)
            "context_close" -> dispatchContextClose(input)
            "context_send" -> dispatchContextSend(input)
            "tool_register" -> dispatchToolRegister(input)
            "tool_invoke" -> dispatchToolInvoke(input)
            "tool_verify" -> dispatchToolVerify(input)
            "ucan_validate" -> dispatchUcanValidate(input)
            "ucan_mint" -> dispatchUcanMint(input)
            "ucan_delegate" -> dispatchUcanDelegate(input)
            "ucan_revoke" -> dispatchUcanRevoke(input)
            "transport_connect" -> dispatchTransportConnect(input)
            "transport_disconnect" -> dispatchTransportDisconnect(input)
            "transport_status" -> dispatchTransportStatus(input)
            "event_log_query" -> dispatchEventLogQuery(input)
            "event_log_verify" -> dispatchEventLogVerify(input)
            "event_log_checkpoint" -> dispatchEventLogCheckpoint(input)
            else -> mapOf("error" to "unsupported_operation")
        }

    private suspend fun dispatchIdentityCreate(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val custody = input["custody"] ?: "in_memory"
            val handle = bridge.identity.create(custody)
            mapOf("handle" to handle.toString(), "custody_type" to custody)
        }

    private suspend fun dispatchIdentityLoad(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val did = input["did"] ?: ""
            val handle = bridge.identity.load(did)
            mapOf("handle" to handle.toString(), "did" to did)
        }

    private suspend fun dispatchIdentityResolve(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val did = input["did"] ?: ""
            val document = bridge.identity.resolve(did)
            mapOf("did" to did, "document" to document)
        }

    private suspend fun dispatchContextCreate(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val identityHandle = input["identity_handle"]?.toLongOrNull() ?: 0L
            val params = input["params"] ?: "{}"
            val handle = bridge.context.create(identityHandle, params)
            mapOf("handle" to handle.toString())
        }

    private suspend fun dispatchContextJoin(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val identityHandle = input["identity_handle"]?.toLongOrNull() ?: 0L
            bridge.context.join(contextHandle, identityHandle)
            mapOf("status" to "joined")
        }

    private suspend fun dispatchContextLeave(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val identityHandle = input["identity_handle"]?.toLongOrNull() ?: 0L
            bridge.context.leave(contextHandle, identityHandle)
            mapOf("status" to "left")
        }

    private suspend fun dispatchContextClose(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val identityHandle = input["identity_handle"]?.toLongOrNull() ?: 0L
            bridge.context.close(contextHandle, identityHandle)
            mapOf("status" to "closed")
        }

    private suspend fun dispatchContextSend(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val identityHandle = input["identity_handle"]?.toLongOrNull() ?: 0L
            val payload = (input["payload"] ?: "").toByteArray()
            bridge.context.send(contextHandle, identityHandle, payload)
            mapOf("status" to "sent")
        }

    private suspend fun dispatchToolRegister(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val definition = input["definition"] ?: "{}"
            val toolId = bridge.tools.register(contextHandle, definition)
            mapOf("tool_id" to toolId)
        }

    private suspend fun dispatchToolInvoke(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val toolId = input["tool_id"] ?: ""
            val toolInput = input["input"] ?: "{}"
            val identityHandle = input["identity_handle"]?.toLongOrNull() ?: 0L
            val ucanToken = input["ucan_token"]
            val proofTokens = input["proof_tokens"]?.let { listOf(it) }
            val output =
                bridge.tools.invoke(
                    contextHandle,
                    toolId,
                    toolInput,
                    identityHandle,
                    ucanToken,
                    proofTokens,
                )
            mapOf("output" to output)
        }

    private suspend fun dispatchToolVerify(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val toolId = input["tool_id"] ?: ""
            val resultJson = bridge.tools.verify(contextHandle, toolId)
            mapOf("result" to resultJson)
        }

    private suspend fun dispatchUcanValidate(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val token = input["encoded"] ?: input["token"] ?: ""
            val capability = input["capability"] ?: ""
            val presentingAgentDid = input["presenting_agent_did"]
            val proofTokens = input["proof_tokens"]?.let { listOf(it) }
            bridge.ucan.validate(contextHandle, token, capability, presentingAgentDid, proofTokens)
            mapOf("status" to "valid")
        }

    private suspend fun dispatchUcanMint(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val memberDid = input["audience_did"] ?: input["member_did"] ?: ""
            val capabilities = input["capabilities"] ?: "[]"
            val token = bridge.ucan.mint(contextHandle, memberDid, capabilities)
            mapOf("token" to token)
        }

    private suspend fun dispatchUcanDelegate(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val delegatorDid = input["delegator_did"] ?: ""
            val delegateeDid = input["delegatee_did"] ?: ""
            val parentToken = input["parent_token"] ?: ""
            val capabilities = input["capabilities"] ?: "[]"
            val token =
                bridge.ucan.delegate(
                    contextHandle,
                    delegatorDid,
                    delegateeDid,
                    parentToken,
                    capabilities,
                )
            mapOf("token" to token)
        }

    private suspend fun dispatchUcanRevoke(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val token = input["token"] ?: input["encoded"] ?: ""
            val revokerDid = input["revoker_did"] ?: ""
            bridge.ucan.revoke(contextHandle, token, revokerDid)
            mapOf("status" to "revoked")
        }

    private suspend fun dispatchTransportConnect(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val relayUrl = input["relay_url"] ?: ""
            val config = Json.encodeToString(buildJsonObject { put("url", relayUrl) })
            val handle = bridge.infra.transportConnect(config)
            mapOf("handle" to handle.toString(), "status" to "connected")
        }

    private suspend fun dispatchTransportDisconnect(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val handle = input["transport_handle"]?.toLongOrNull() ?: 0L
            bridge.infra.transportDisconnect(handle)
            mapOf("status" to "disconnected")
        }

    private suspend fun dispatchTransportStatus(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val handle = input["transport_handle"]?.toLongOrNull() ?: 0L
            val status = bridge.infra.transportStatus(handle)
            mapOf("status_json" to status)
        }

    private suspend fun dispatchEventLogQuery(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val filter = input["filter"] ?: "{}"
            val result = bridge.infra.eventLogQuery(contextHandle, filter)
            mapOf("result" to result)
        }

    private suspend fun dispatchEventLogVerify(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val claim = input["claim"] ?: input["proof"] ?: "{}"
            val valid = bridge.infra.eventLogVerify(contextHandle, claim)
            mapOf("is_valid" to valid.toString())
        }

    private suspend fun dispatchEventLogCheckpoint(input: Map<String, String>): Map<String, String> =
        catchBridge {
            val contextHandle = input["context_handle"]?.toLongOrNull() ?: 0L
            val identityHandle = input["identity_handle"]?.toLongOrNull() ?: 0L
            val epoch = input["epoch"]?.toLongOrNull() ?: 0L
            val result = bridge.infra.eventLogCheckpoint(contextHandle, identityHandle, epoch)
            mapOf("checkpoint" to result)
        }

    private suspend fun catchBridge(block: suspend () -> Map<String, String>): Map<String, String> =
        try {
            block()
        } catch (e: BridgeException) {
            mapOf("error" to e.code)
        } catch (
            @Suppress("TooGenericExceptionCaught") e: Exception,
        ) {
            mapOf("error" to "unknown", "detail" to (e.message ?: e.toString()))
        }
}
