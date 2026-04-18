/*
 * Long-lived Kotlin JSON-RPC server for cross-bridge parity testing
 * (ADR-046). Mirrors `node_bridge_runner.ts` and `swift_bridge_runner`
 * one-to-one on the wire.
 *
 * Wire format (HTTP-style) — identical across all three runners:
 *
 *     Content-Length: N\r\n
 *     \r\n
 *     <N bytes of JSON>
 *
 * Request: `{id, op, args, bridgeMode}` — bridgeMode MUST be
 * "uniffi-kotlin" for this runner. Any other value is rejected.
 * Response: `{id, ok: true, result: {...}}` on success or
 *           `{id, ok: false, error: {type, code, message}}` on failure.
 *
 * Transport errors that prevent parsing or emitting a frame are logged
 * to stderr as JSON events (`event: bridge_parity_runner_*`) and cause
 * the runner to exit non-zero; they are NOT surfaced as bridge-level
 * errors in-band.
 */

@file:Suppress("TooManyFunctions") // JSON-RPC dispatch table is naturally wide.

package works.limn.scp.parity

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

// ---------------------------------------------------------------------------
// JSON codec
// ---------------------------------------------------------------------------

private val JSON = Json {
    // Preserve nulls for parity with the Bun runner, where an explicit
    // `null` reply field may differ semantically from an absent one.
    explicitNulls = true
    // Accept unknown keys so the harness can evolve the request shape
    // without breaking the runner.
    ignoreUnknownKeys = true
}

// ---------------------------------------------------------------------------
// Frame I/O — length-prefixed, HTTP-style.
//
// Caps match runner_client.py's MAX_HEADER_BYTES / MAX_FRAME_BYTES so a
// misbehaving harness cannot OOM us any more than it can OOM itself.
// ---------------------------------------------------------------------------

private const val MAX_HEADER_BYTES = 4 * 1024
private const val MAX_FRAME_BYTES = 16 * 1024 * 1024
private val HEADER_TERMINATOR = byteArrayOf(13, 10, 13, 10)
private val HEADER_REGEX = Regex("""Content-Length:\s*(\d+)""", RegexOption.IGNORE_CASE)

private fun eprint(line: String) {
    System.err.println(line)
    System.err.flush()
}

/**
 * Read one length-prefixed frame from [input]. Returns the decoded
 * request or null on EOF (clean shutdown at frame boundary). Throws
 * [RunnerProtocolError] on malformed frames — the main loop emits an
 * error response and continues (except on EOF, which terminates).
 */
private fun readFrame(input: InputStream): RawRequest? {
    // Accumulate header bytes until the terminator or cap.
    val headerBuf = ByteArrayOutputStream()
    while (true) {
        val b = input.read()
        if (b == -1) {
            return if (headerBuf.size() == 0) null else throw RunnerProtocolError(
                "EOF mid-header (buffered=${headerBuf.size()})"
            )
        }
        headerBuf.write(b)
        val size = headerBuf.size()
        if (size > MAX_HEADER_BYTES) {
            throw RunnerProtocolError("header exceeded $MAX_HEADER_BYTES bytes")
        }
        if (size >= HEADER_TERMINATOR.size) {
            val buf = headerBuf.toByteArray()
            var match = true
            for (i in HEADER_TERMINATOR.indices) {
                if (buf[size - HEADER_TERMINATOR.size + i] != HEADER_TERMINATOR[i]) {
                    match = false; break
                }
            }
            if (match) break
        }
    }
    // Parse header, read body.
    val headerBytes = headerBuf.toByteArray()
    val headerText = String(
        headerBytes, 0, headerBytes.size - HEADER_TERMINATOR.size,
        StandardCharsets.UTF_8
    )
    val match = HEADER_REGEX.find(headerText)
        ?: throw RunnerProtocolError("missing Content-Length header: $headerText")
    val length = match.groupValues[1].toIntOrNull()
        ?: throw RunnerProtocolError("invalid Content-Length: $headerText")
    if (length < 0 || length > MAX_FRAME_BYTES) {
        throw RunnerProtocolError("Content-Length out of range: $length")
    }
    val body = ByteArray(length)
    var read = 0
    while (read < length) {
        val n = input.read(body, read, length - read)
        if (n == -1) throw RunnerProtocolError("EOF reading body ($read/$length)")
        read += n
    }
    val bodyText = String(body, StandardCharsets.UTF_8)
    return try {
        JSON.decodeFromString<RawRequest>(bodyText)
    } catch (e: Exception) {
        throw RunnerProtocolError("invalid request JSON: ${e.message}")
    }
}

private fun writeFrame(output: OutputStream, json: String) {
    val body = json.toByteArray(StandardCharsets.UTF_8)
    val header = "Content-Length: ${body.size}\r\n\r\n".toByteArray(StandardCharsets.UTF_8)
    output.write(header)
    output.write(body)
    output.flush()
}

private class RunnerProtocolError(message: String) : RuntimeException(message)

// ---------------------------------------------------------------------------
// Request / response types
//
// bridgeMode is camelCase on the wire (mirrors node_bridge_runner.ts) —
// the field rename avoids collision with the TS DOM `RequestMode` type
// on that side. Kotlin doesn't care, but keeping the exact same wire
// format is the whole point of the runner.
// ---------------------------------------------------------------------------

@Serializable
private data class RawRequest(
    val id: Int = 0,
    val op: String,
    val args: JsonObject = buildJsonObject { },
    val bridgeMode: String = ""
)

private fun okResponse(id: Int, result: JsonObject): String {
    // Build the response manually to match the Bun runner's exact shape:
    // {"id": N, "ok": true, "result": {...}}.
    val obj = buildJsonObject {
        put("id", JsonPrimitive(id))
        put("ok", JsonPrimitive(true))
        put("result", result)
    }
    return JSON.encodeToString(JsonElement.serializer(), obj)
}

private fun errResponse(id: Int, type: String, code: String, message: String): String {
    val obj = buildJsonObject {
        put("id", JsonPrimitive(id))
        put("ok", JsonPrimitive(false))
        put(
            "error",
            buildJsonObject {
                put("type", JsonPrimitive(type))
                put("code", JsonPrimitive(code))
                put("message", JsonPrimitive(message))
            }
        )
    }
    return JSON.encodeToString(JsonElement.serializer(), obj)
}

// Extract an SCP-{CATEGORY}-{NNNN} code from an error message. Matches
// the Bun runner's regex — kept in lockstep so bridge-side errors
// surface the same code field to the harness.
private val SCP_CODE_REGEX = Regex("""SCP-[A-Z]+-\d+""")

private fun extractScpCode(message: String): String =
    SCP_CODE_REGEX.find(message)?.value ?: "UNKNOWN"

// ---------------------------------------------------------------------------
// Op implementations — consume UniFFI-generated `uniffi.scp.*` directly.
// Parity is what we want to test, so we do NOT go through the scp-kt
// SDK wrappers (which would add a layer of semantic sugar that could
// diverge from the other runners).
// ---------------------------------------------------------------------------

private fun buildContextParams(
    ceiling: List<String> = listOf("messages:read", "messages:write")
): uniffi.scp.ContextParams =
    uniffi.scp.ContextParams(
        mode = uniffi.scp.ContextMode.ENCRYPTED,
        ceiling = ceiling,
        ceilingPolicy = uniffi.scp.CeilingPolicy.IMMUTABLE,
        governance = uniffi.scp.GovernanceModel.SINGLE_ADMIN,
        memoryScope = uniffi.scp.MemoryScope.EPHEMERAL,
        ttlSeconds = 0uL,
        promotable = false,
        minProtocolVersion = 0u,
        maxChainDepth = null,
        maxNestingDepth = null,
        sessionCap = null,
        economicPolicy = null,
        consequenceRulesJson = null,
        consequenceConfigJson = null
    )

private fun ceilingFromArgs(
    args: JsonObject,
    default: List<String>
): List<String> {
    val raw = args["ceiling"] ?: return default
    val array = raw as? kotlinx.serialization.json.JsonArray ?: return default
    return array.map { it.jsonPrimitive.content }
}

private suspend fun opIdentityCreate(args: JsonObject): JsonObject {
    val custody = args["custody"]?.jsonPrimitive?.content ?: "in_memory"
    val identity = uniffi.scp.identityCreate(custody)
    return buildJsonObject {
        put("did", JsonPrimitive(identity.did()))
        put("custody", JsonPrimitive(custody))
    }
}

private suspend fun opContextCreate(args: JsonObject): JsonObject {
    val paramsArg = args["params"]?.jsonObject ?: buildJsonObject { }
    val mode = paramsArg["mode"]?.jsonPrimitive?.content ?: "encrypted"
    val identity = uniffi.scp.identityCreate("in_memory")
    val handle = uniffi.scp.contextCreate(identity, buildContextParams())
    return buildJsonObject {
        put("context_id", JsonPrimitive(handle.contextId()))
        put("creator_did", JsonPrimitive(identity.did()))
        put("mode", JsonPrimitive(mode))
    }
}

@Suppress("UnusedParameter")
private suspend fun opInvalidCapability(args: JsonObject): JsonObject {
    // Same malformed-challenge path as the other runners: the challenge
    // JSON fails shape validation at SCP-IDENT-1038 before any DID
    // lookup happens. `scpidSign` takes an Identity object (not a DID
    // string) in the Kotlin/Swift bridges, so we create a real identity
    // and send it the bad challenge.
    val badChallenge =
        """{"protocol":"scpid/1","nonce":"00","audience":"x","issued_at":0,"expires_at":0}"""
    return try {
        val identity = uniffi.scp.identityCreate("in_memory")
        uniffi.scp.scpidSign(identity, "#active", badChallenge)
        buildJsonObject {
            put(
                "error",
                buildJsonObject {
                    put("type", JsonPrimitive("none"))
                    put("code", JsonPrimitive("NONE"))
                    put("message", JsonPrimitive("no error raised"))
                }
            )
        }
    } catch (e: Throwable) {
        val message = e.message ?: e.toString()
        buildJsonObject {
            put(
                "error",
                buildJsonObject {
                    put("type", JsonPrimitive(e::class.simpleName ?: "Exception"))
                    put("code", JsonPrimitive(extractScpCode(message)))
                    put("message", JsonPrimitive(message))
                }
            )
        }
    }
}

@Suppress("UnusedParameter")
private suspend fun opEventLogAppend(args: JsonObject): JsonObject {
    val identity = uniffi.scp.identityCreate("in_memory")
    val handle = uniffi.scp.contextCreate(identity, buildContextParams())
    val events = uniffi.scp.eventLogQuery(handle, null)
    val first = events.firstOrNull()
    return buildJsonObject {
        if (first == null) {
            put("event_count", JsonPrimitive(0))
            put("first_event_type", JsonPrimitive(""))
            put("first_sequence", JsonPrimitive(0))
        } else {
            put("event_count", JsonPrimitive(events.size))
            put("first_event_type", JsonPrimitive(first.eventType))
            // UniFFI generates `sequence: ULong`; JSON has no unsigned
            // integer type, so we marshal as Long. Parity values are
            // well below Long.MAX_VALUE.
            put("first_sequence", JsonPrimitive(first.sequence.toLong()))
        }
    }
}

// -- ops 6-10 ------------------------------------------------------------

private const val PARITY_TOOL_NAME = "parity_probe"
private val PARITY_TOOL_CEILING = listOf(
    "messages:read",
    "messages:write",
    "tool:register",
    "tool_invoke:*"
)

@Suppress("UnusedParameter")
private suspend fun opToolRegister(args: JsonObject): JsonObject {
    val ceiling = ceilingFromArgs(args, PARITY_TOOL_CEILING)
    val identity = uniffi.scp.identityCreate("in_memory")
    val handle = uniffi.scp.contextCreate(identity, buildContextParams(ceiling))
    val inputSchema = """{"type":"object","properties":{"x":{"type":"integer"}}}"""
    val outputSchema = """{"type":"object","properties":{"y":{"type":"integer"}}}"""
    val toolId = uniffi.scp.toolRegister(
        handle,
        uniffi.scp.ToolDefinition(
            name = PARITY_TOOL_NAME,
            description = "parity harness probe tool",
            inputSchemaJson = inputSchema,
            outputSchemaJson = outputSchema,
            operatorDid = identity.did(),
            testVectorsJson = null,
            implementationHash = null,
            cost = null
        )
    )
    return buildJsonObject { put("tool_id", JsonPrimitive(toolId)) }
}

private suspend fun opUcanMint(args: JsonObject): JsonObject {
    val memberDid = args["member_did"]?.jsonPrimitive?.content
        ?: "did:dht:zparitymemberparitymemberparitymemberparitymember"
    val capabilities = (args["capabilities"] as? kotlinx.serialization.json.JsonArray)
        ?.map { it.jsonPrimitive.content }
        ?: listOf("messages:read")
    val ceiling = ceilingFromArgs(args, listOf("messages:read", "messages:write"))
    val identity = uniffi.scp.identityCreate("in_memory")
    val handle = uniffi.scp.contextCreate(identity, buildContextParams(ceiling))
    val token = uniffi.scp.ucanMint(handle, memberDid, capabilities, null)
    return buildJsonObject {
        put("issuer", JsonPrimitive(token.issuer()))
        put("audience", JsonPrimitive(token.audience()))
        put("capability_count", JsonPrimitive(token.capabilities().size))
    }
}

private suspend fun opUcanValidateMalformed(args: JsonObject): JsonObject {
    // UniFFI wraps parse_ucan errors with SCP-PERM-3002 (diverges from
    // PyO3/NAPI SCP-PERM-3001). The seed_operations.py OpSpec xfails
    // uniffi-kotlin for this op until the codes are aligned upstream.
    val ceiling = ceilingFromArgs(args, listOf("messages:read", "messages:write"))
    val identity = uniffi.scp.identityCreate("in_memory")
    val handle = uniffi.scp.contextCreate(identity, buildContextParams(ceiling))
    return try {
        uniffi.scp.ucanValidate(
            handle,
            "not.a.jwt",
            "scp:ctx:any/messages:read",
            null,
            null
        )
        buildJsonObject {
            put(
                "error",
                buildJsonObject {
                    put("type", JsonPrimitive("none"))
                    put("code", JsonPrimitive("NONE"))
                }
            )
        }
    } catch (e: Throwable) {
        val message = e.message ?: e.toString()
        buildJsonObject {
            put(
                "error",
                buildJsonObject {
                    put("type", JsonPrimitive(e::class.simpleName ?: "Exception"))
                    put("code", JsonPrimitive(extractScpCode(message)))
                }
            )
        }
    }
}

@Suppress("UnusedParameter")
private suspend fun opTransportStatus(args: JsonObject): JsonObject {
    // UniFFI's `transport_status` now accepts an Optional<TransportManager>;
    // when absent, it returns the stateless BridgeInstance-level snapshot —
    // the same shape exposed by PyO3 and WASM. The parity harness always
    // exercises the handleless probe (no transport_connect, no relay
    // fixture), so every bridge reports `connected: false` here.
    val status = uniffi.scp.transportStatus(null)
    return buildJsonObject {
        put("connected", JsonPrimitive(status.connected))
        put(
            "relay_url",
            status.relayUrl?.let { JsonPrimitive(it) } ?: kotlinx.serialization.json.JsonNull
        )
        put(
            "latency_ms",
            status.latencyMs?.let { JsonPrimitive(it) } ?: kotlinx.serialization.json.JsonNull
        )
    }
}

@Suppress("UnusedParameter")
private suspend fun opEventLogQueryFiltered(args: JsonObject): JsonObject {
    val filter = args["filter"]?.jsonObject ?: buildJsonObject {
        put("event_type", JsonPrimitive("ContextCreated"))
    }
    val identity = uniffi.scp.identityCreate("in_memory")
    val handle = uniffi.scp.contextCreate(identity, buildContextParams())
    val events = uniffi.scp.eventLogQuery(handle, JSON.encodeToString(JsonElement.serializer(), filter))
    val first = events.firstOrNull()
    return buildJsonObject {
        put("event_count", JsonPrimitive(events.size))
        put("first_event_type", JsonPrimitive(first?.eventType ?: ""))
    }
}

private suspend fun opSignMessage(args: JsonObject): JsonObject {
    val audience = args["audience"]?.jsonPrimitive?.content
        ?: "https://parity-test.example.com"
    val ttl = args["ttl_seconds"]?.jsonPrimitive?.longOrNull?.toULong() ?: 60uL
    val identity = uniffi.scp.identityCreate("in_memory")
    val challenge = uniffi.scp.scpidChallenge(audience, ttl)
    val responseJson = uniffi.scp.scpidSign(identity, "#active", challenge)
    val parsed = JSON.parseToJsonElement(responseJson).jsonObject
    return buildJsonObject {
        put("protocol", JsonPrimitive(parsed["protocol"]?.jsonPrimitive?.content ?: ""))
        put("did", JsonPrimitive(parsed["did"]?.jsonPrimitive?.content ?: ""))
        put(
            "signing_key_id",
            JsonPrimitive(parsed["signing_key_id"]?.jsonPrimitive?.content ?: "")
        )
        put("signature", JsonPrimitive(parsed["signature"]?.jsonPrimitive?.content ?: ""))
    }
}

private suspend fun dispatch(req: RawRequest): String {
    return try {
        val result = when (req.op) {
            "identity_create" -> opIdentityCreate(req.args)
            "context_create" -> opContextCreate(req.args)
            "invalid_capability_rejected" -> opInvalidCapability(req.args)
            "event_log_append" -> opEventLogAppend(req.args)
            "sign_message" -> opSignMessage(req.args)
            "tool_register" -> opToolRegister(req.args)
            "ucan_mint" -> opUcanMint(req.args)
            "ucan_validate_malformed" -> opUcanValidateMalformed(req.args)
            "transport_status" -> opTransportStatus(req.args)
            "event_log_query_filtered" -> opEventLogQueryFiltered(req.args)
            else -> return errResponse(
                req.id,
                type = "UnknownOp",
                code = "TEST-PARITY-1001",
                message = "unknown op: ${req.op}"
            )
        }
        okResponse(req.id, result)
    } catch (e: Throwable) {
        val message = e.message ?: e.toString()
        errResponse(
            req.id,
            type = e::class.simpleName ?: "Exception",
            code = extractScpCode(message),
            message = message
        )
    }
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

fun main() {
    // Emit a startup diagnostic in the same shape as the Bun runner.
    // Parallel to bridge_parity_runner_loaded — lets operators confirm
    // the runner is up before the first RPC.
    eprint("""{"event":"bridge_parity_runner_loaded","runner":"kotlin","bridge":"uniffi-kotlin"}""")

    val input = BufferedInputStream(System.`in`)
    val output = BufferedOutputStream(System.out)

    runBlocking {
        while (true) {
            val req = try {
                readFrame(input) ?: break // clean EOF
            } catch (e: RunnerProtocolError) {
                writeFrame(
                    output,
                    errResponse(
                        id = 0,
                        type = "FrameError",
                        code = "TEST-PARITY-1000",
                        message = e.message ?: "frame error"
                    )
                )
                continue
            }

            when (req.op) {
                "shutdown" -> {
                    writeFrame(output, okResponse(req.id, buildJsonObject { }))
                    return@runBlocking
                }
                "reset" -> {
                    // UniFFI Kotlin bindings hold their own module-global
                    // state (ContextManager, identity registry). Nothing
                    // runner-local to clear — return success so the
                    // harness's per-test reset protocol is honored.
                    writeFrame(output, okResponse(req.id, buildJsonObject { }))
                    continue
                }
                else -> {
                    if (req.bridgeMode != "uniffi-kotlin") {
                        writeFrame(
                            output,
                            errResponse(
                                req.id,
                                type = "ProtocolError",
                                code = "TEST-PARITY-1003",
                                message = "kotlin runner only accepts bridgeMode=uniffi-kotlin, got: ${req.bridgeMode}"
                            )
                        )
                        continue
                    }
                    writeFrame(output, dispatch(req))
                }
            }
        }
    }
}
