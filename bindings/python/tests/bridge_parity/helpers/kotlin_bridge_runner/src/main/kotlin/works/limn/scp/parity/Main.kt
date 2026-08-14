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
 * ADR-048 / #1549 Phase 4 PR 4: every UniFFI bridge operation is now a
 * per-instance method on the `uniffi.scp.Scp` opaque class. Each op
 * constructs a fresh `Scp` via `Scp().use { ... }` so handles stay
 * scoped to the call and the native resource is released even on
 * exception. No free-function façade remains.
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
// ---------------------------------------------------------------------------

@Serializable
private data class RawRequest(
    val id: Int = 0,
    val op: String,
    val args: JsonObject = buildJsonObject { },
    val bridgeMode: String = ""
)

private fun okResponse(id: Int, result: JsonObject): String {
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

private val SCP_CODE_REGEX = Regex("""SCP-[A-Z]+-\d+""")

private fun extractScpCode(message: String): String =
    SCP_CODE_REGEX.find(message)?.value ?: "UNKNOWN"

// ---------------------------------------------------------------------------
// Op implementations — construct a fresh `uniffi.scp.Scp` per op and
// dispatch per-instance methods on it (ADR-048). Parity is what we want
// to test, so we do NOT go through the scp-kt SDK wrappers.
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

/**
 * Decode a 64-char hex string into a 32-byte `ByteArray` seed for
 * `scp.identityCreate(custody, testingSeed)`. Matches
 * `node_bridge_runner.ts::seedFromHex` — the parity harness passes a
 * `seed_hex` arg so every bridge derives byte-identical key material
 * from the same 32 bytes (ADR-046).
 */
private fun seedFromHex(hex: String): ByteArray {
    require(hex.length == 64) {
        "seed_hex must be 64 chars (32 bytes), got ${hex.length}"
    }
    val bytes = ByteArray(32)
    for (i in 0 until 32) {
        val hi = Character.digit(hex[i * 2], 16)
        val lo = Character.digit(hex[i * 2 + 1], 16)
        require(hi >= 0 && lo >= 0) {
            "seed_hex contains non-hex character at index ${i * 2}"
        }
        bytes[i] = ((hi shl 4) or lo).toByte()
    }
    return bytes
}

private suspend fun opIdentityCreate(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val custody = args["custody"]?.jsonPrimitive?.content ?: "in_memory"
        val seed = args["seed_hex"]?.jsonPrimitive?.content?.let { seedFromHex(it) }
        val identity = scp.identityCreate(custody, seed)
        buildJsonObject {
            put("did", JsonPrimitive(identity.did()))
            put("custody", JsonPrimitive(custody))
            val verifyingKeyHex = identity.verifyingKey()
            if (verifyingKeyHex != null) {
                put("verifying_key", JsonPrimitive(verifyingKeyHex))
            }
        }
    }

private suspend fun opContextCreate(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val paramsArg = args["params"]?.jsonObject ?: buildJsonObject { }
        val mode = paramsArg["mode"]?.jsonPrimitive?.content ?: "encrypted"
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams())
        buildJsonObject {
            put("context_id", JsonPrimitive(handle.contextId()))
            put("creator_did", JsonPrimitive(identity.did()))
            put("mode", JsonPrimitive(mode))
        }
    }

@Suppress("UnusedParameter")
private suspend fun opInvalidCapability(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        // UniFFI `scpidSign` takes an opaque `Identity` handle (not a DID
        // string), so feed a real identity a malformed challenge: shape
        // validation rejects with SCP-IDENT-1038 before any DID lookup.
        // Matches the other runners.
        val badChallenge =
            """{"protocol":"scpid/1","nonce":"00","audience":"x","issued_at":0,"expires_at":0}"""
        try {
            val identity = scp.identityCreate("in_memory", null)
            scp.scpidSign(identity, "#active", badChallenge, null)
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
private suspend fun opEventLogAppend(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams())
        val events = scp.eventLogQuery(handle, null)
        val first = events.firstOrNull()
        buildJsonObject {
            if (first == null) {
                put("event_count", JsonPrimitive(0))
                put("first_event_type", JsonPrimitive(""))
                put("first_sequence", JsonPrimitive(0))
            } else {
                put("event_count", JsonPrimitive(events.size))
                put("first_event_type", JsonPrimitive(first.eventType))
                put("first_sequence", JsonPrimitive(first.sequence.toLong()))
            }
        }
    }

// -- ops 6-10 ------------------------------------------------------------

private const val PARITY_OUTLET_NAME = "parity_probe"
private val PARITY_OUTLET_CEILING = listOf(
    "messages:read",
    "messages:write",
    "outlet:register",
    "outlet_call:*"
)

@Suppress("UnusedParameter")
private suspend fun opOutletRegister(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val ceiling = ceilingFromArgs(args, PARITY_OUTLET_CEILING)
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams(ceiling))
        val inputSchema =
            """{"type":"object","properties":{"x":{"type":"integer"},"label":{"type":"string"}}}"""
        val outputSchema =
            """{"type":"object","properties":{"y":{"type":"integer"},"status":{"type":"string"}}}"""
        val outletId = scp.outletRegister(
            handle,
            uniffi.scp.OutletDefinition(
                name = PARITY_OUTLET_NAME,
                description = "parity harness probe outlet",
                kind = uniffi.scp.OutletKind.ACTION,
                inputSchemaJson = inputSchema,
                outputSchemaJson = outputSchema,
                operatorDid = identity.did(),
                testVectorsJson = null,
                implementationHash = null,
                cost = null
            )
        )
        buildJsonObject { put("outlet_id", JsonPrimitive(outletId)) }
    }

private suspend fun opUcanMint(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val memberDid = args["member_did"]?.jsonPrimitive?.content
            ?: "did:dht:zparitymemberparitymemberparitymemberparitymember"
        val capabilities = (args["capabilities"] as? kotlinx.serialization.json.JsonArray)
            ?.map { it.jsonPrimitive.content }
            ?: listOf("messages:read")
        val ceiling = ceilingFromArgs(args, listOf("messages:read", "messages:write"))
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams(ceiling))
        val token = scp.ucanMint(handle, memberDid, capabilities, null)
        buildJsonObject {
            put("issuer", JsonPrimitive(token.issuer()))
            put("audience", JsonPrimitive(token.audience()))
            put("capability_count", JsonPrimitive(token.capabilities().size))
        }
    }

private suspend fun opUcanValidateMalformed(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        // UniFFI wraps parse_ucan errors with SCP-PERM-3002 (diverges from
        // PyO3/NAPI SCP-PERM-3001). The seed_operations.py OpSpec xfails
        // uniffi-kotlin for this op until the codes are aligned upstream.
        val ceiling = ceilingFromArgs(args, listOf("messages:read", "messages:write"))
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams(ceiling))
        try {
            scp.ucanValidate(
                handle,
                "not.a.jwt",
                "scp:ctx:any/messages:read",
                // Fail-closed presenting-agent gate: supply one so the malformed
                // JWT is rejected at PARSE (the behavior under test).
                identity.did(),
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

private suspend fun opUcanEvaluateMalformed(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        // ucan_evaluate is the structured read-only counterpart to ucan_validate.
        // A malformed JWT fails the FFI token validator before reaching the
        // pipeline, surfacing as a thrown error whose code aligns across bridges
        // (canonical SCP-PERM-3001 via the shared From<UcanError> mapping).
        val ceiling = ceilingFromArgs(args, listOf("messages:read", "messages:write"))
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams(ceiling))
        try {
            scp.ucanEvaluate(
                handle,
                "not.a.jwt",
                "scp:ctx:any/messages:read",
                // Fail-closed presenting-agent gate: supply one so the malformed
                // JWT is rejected at PARSE (the behavior under test).
                identity.did(),
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

private suspend fun opUcanEvaluateStructured(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        // Mint a VALID root token granting `messages:read`, then evaluate it
        // requiring `messages:write` (a capability the token does NOT grant).
        // Core evaluate_ucan short-circuits at grant-match and returns the
        // partial-false struct WITHOUT throwing — the no-throw counterpart to
        // opUcanEvaluateMalformed. All six booleans are compared across bridges.
        val memberDid = args["member_did"]?.jsonPrimitive?.content
            ?: "did:dht:zparitymemberparitymemberparitymemberparitymember"
        val capabilities = (args["capabilities"] as? kotlinx.serialization.json.JsonArray)
            ?.map { it.jsonPrimitive.content }
            ?: listOf("messages:read")
        val requiredCap = args["required_capability"]?.jsonPrimitive?.content ?: "messages:write"
        val ceiling = ceilingFromArgs(args, listOf("messages:read", "messages:write"))
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams(ceiling))
        val token = scp.ucanMint(handle, memberDid, capabilities, null)
        val required = "scp:ctx:${handle.contextId()}/$requiredCap"
        val result = scp.ucanEvaluate(handle, token.encoded(), required, memberDid, null)
        buildJsonObject {
            put("tokens_valid", JsonPrimitive(result.tokensValid))
            put("signatures_valid", JsonPrimitive(result.signaturesValid))
            put("within_ceiling", JsonPrimitive(result.withinCeiling))
            put("nonce_valid", JsonPrimitive(result.nonceValid))
            put("not_revoked", JsonPrimitive(result.notRevoked))
            put("time_bounds_valid", JsonPrimitive(result.timeBoundsValid))
        }
    }

@Suppress("UnusedParameter")
private suspend fun opTransportStatus(args: JsonObject): JsonObject =
    // ADR-048 §7a: UniFFI now exposes a handleless `transportManagerStatus()`
    // alongside the handle-taking `transportStatus(manager)`, matching the
    // PyO3 / NAPI probe contract. The parity harness drives the
    // handleless path so no relay fixture is needed on the UniFFI runners.
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val status = scp.transportManagerStatus()
        buildJsonObject {
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

// Shape-valid `did:dht:z…` DID guaranteed NOT to be in any bridge's
// identity registry. Mirrors `seed_operations.py::FAKE_UNREGISTERED_DID`.
private const val FAKE_UNREGISTERED_DID =
    "did:dht:znever1never1never1never1never1never1never1never1never1never1neva"

@Suppress("UnusedParameter")
private suspend fun opUnregisteredDidRejected(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use {
        // UniFFI `scpidSign` takes an opaque `Identity` handle rather
        // than a DID string, so the bridge-local registry lookup path
        // the PyO3/NAPI bridges exercise is not reachable. Instead,
        // we exercise the SAME error code via `identityResolve` on the
        // fake DID: its 64-char zbase32 suffix decodes to 40 bytes (not
        // the 32 required by did:dht), so `DidDht::extract_public_key`
        // returns `IdentityError::InvalidDidFormat` locally (no DHT
        // round-trip). The bridge's blanket `From<IdentityError>`
        // mapping surfaces it as SCP-IDENT-1001 — the committed code
        // every bridge agrees on. `identityResolve` is a module-level free
        // function (ADR-048 §1), so it is called on `uniffi.scp`, not the
        // instance.
        try {
            uniffi.scp.identityResolve(FAKE_UNREGISTERED_DID)
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
private suspend fun opEventLogQueryFiltered(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val filter = args["filter"]?.jsonObject ?: buildJsonObject {
            put("event_type", JsonPrimitive("ContextCreated"))
        }
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams())
        val events = scp.eventLogQuery(
            handle,
            JSON.encodeToString(JsonElement.serializer(), filter)
        )
        val first = events.firstOrNull()
        buildJsonObject {
            put("event_count", JsonPrimitive(events.size))
            put("first_event_type", JsonPrimitive(first?.eventType ?: ""))
        }
    }

// Drives the PRODUCTION UniFFI verify path (`Scp.eventLogVerify` →
// `Proof`) — NOT the never-swapped `NativeBindings` scaffold. Pins the
// honest proof shape: a returned proof IS the positive answer (no
// `verified` flag) and its details carry the checkable Merkle material
// plus the one-snapshot `leaf_count`. Mirrors
// `seed_operations.py::_py_event_log_verify_inclusion`.
@Suppress("UnusedParameter")
private suspend fun opEventLogVerifyInclusion(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams())
        // `ContextCreated` is leaf 0 of the AUTHORITATIVE log on every
        // bridge.
        val proof = scp.eventLogVerify(
            handle,
            """{"type":"inclusion","leaf_index":0}"""
        )
        val details = JSON.parseToJsonElement(proof.detailsJson).jsonObject
        buildJsonObject {
            put("proof_type", JsonPrimitive(proof.proofType))
            put("leaf_count", JsonPrimitive(details["leaf_count"]?.jsonPrimitive?.longOrNull ?: -1L))
            put("has_leaf_hash", JsonPrimitive(details.containsKey("leaf_hash")))
            put("has_path", JsonPrimitive(details.containsKey("path")))
            put("has_root", JsonPrimitive(details.containsKey("root")))
        }
    }

// GitHub #1933 AC 4: an absence proof for a REAL lifecycle event must
// FAIL with SCP-CTX-2139 identically on every bridge. Extracts the
// `ContextCreated` leaf hash from this bridge's own inclusion proof so
// the absence claim provably names an event that IS in the
// authoritative log. Mirrors
// `seed_operations.py::_py_event_log_absence_rejected`.
@Suppress("UnusedParameter")
private suspend fun opEventLogAbsenceRejected(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams())
        val inclusion = scp.eventLogVerify(
            handle,
            """{"type":"inclusion","leaf_index":0}"""
        )
        val details = JSON.parseToJsonElement(inclusion.detailsJson).jsonObject
        val leafHash = details["leaf_hash"]?.jsonPrimitive?.content ?: ""
        try {
            scp.eventLogVerify(
                handle,
                """{"type":"absence","event_hash":"$leafHash"}"""
            )
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

// Reproduces the F3 divergence precondition (GitHub #1933) through the
// PUBLIC surface — the mechanical guard ops 12/13 CANNOT provide because
// they run on a pristine context whose bridge-local tree still equals the
// authoritative log. Diverges the trees via `provenanceAttach`, reads the
// AUTHORITATIVE ContextCreated hash from the query path (independent of the
// verify path under test), then claims it absent. A correct bridge proves
// over the authoritative log where the hash IS present and rejects with
// SCP-CTX-2139; a bridge regressed to the divergent local tree would mint a
// verifying absence proof. Mirrors
// `seed_operations.py::_py_event_log_absence_over_divergent_local_tree_rejected`.
@Suppress("UnusedParameter")
private suspend fun opEventLogAbsenceOverDivergentLocalTree(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams())
        val did = identity.did()
        // Diverge the bridge-local tree from the authoritative log via a
        // real public bridge call. The source context is missing, so only the
        // `ProvenanceReceived` target-side leaf lands on the bridge-local tree
        // (a leaf NOT in the authoritative log); the source-side
        // `ProvenanceAttached` append is dropped best-effort.
        scp.provenanceAttach(
            "parity-prov-source",
            "persistent",
            "full",
            listOf(did),
            handle.contextId(),
            did,
            null
        )
        // AUTHORITATIVE ContextCreated leaf hash from the query path —
        // independent of the verify path under test.
        val events = scp.eventLogQuery(handle, """{"event_type":"ContextCreated"}""")
        val payload = JSON.parseToJsonElement(events.first().payloadJson).jsonObject
        val authHash = payload["hash"]?.jsonPrimitive?.content ?: ""
        try {
            scp.eventLogVerify(handle, """{"type":"absence","event_hash":"$authHash"}""")
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

// The mechanical cross-bridge guard for Fix 1 (GitHub #1933): a malformed
// claim carries SCP-VALID-7000 on every bridge. Feeds a malformed inclusion
// claim (missing `leaf_index`) over a readable log and reports the code.
// Mirrors `seed_operations.py::_py_event_log_verify_malformed_claim`.
@Suppress("UnusedParameter")
private suspend fun opEventLogVerifyMalformedClaim(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams())
        try {
            // `type` present and valid, `leaf_index` MISSING — malformed
            // input the inclusion arm rejects with VALID-7000.
            scp.eventLogVerify(handle, """{"type":"inclusion"}""")
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

// The direct cross-bridge regression guard for the `context_events` twin
// (GitHub #1933). Reads the AUTHORITATIVE root + count from the verify path,
// diverges the bridge-local tree via `provenanceAttach` (a `ProvenanceReceived`
// leaf NOT in the authoritative log), then asserts the `mcpContextEvents`
// summary STILL commits to the authoritative log. Raw `merkle_root` bytes are
// not compared cross-bridge (the fresh `ContextCreated` leaf carries a
// wall-clock timestamp); the SEMANTIC `root_matches_authoritative` invariant is.
// Mirrors `seed_operations.py::_py_mcp_context_events_authoritative`.
@Suppress("UnusedParameter")
private suspend fun opMcpContextEventsAuthoritative(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val identity = scp.identityCreate("in_memory", null)
        val handle = scp.contextCreate(identity, buildContextParams())
        val did = identity.did()
        // AUTHORITATIVE root + count from the verify path — independent of the
        // MCP summary surface under test.
        val proof = scp.eventLogVerify(handle, """{"type":"inclusion","leaf_index":0}""")
        val details = JSON.parseToJsonElement(proof.detailsJson).jsonObject
        val authRoot = details["root"]?.jsonPrimitive?.content ?: ""
        val authCount = details["leaf_count"]?.jsonPrimitive?.longOrNull ?: -1L
        // Diverge the bridge-local tree via a real public bridge call (appends
        // a `ProvenanceReceived` leaf NOT in the authoritative log).
        scp.provenanceAttach(
            "parity-prov-source",
            "persistent",
            "full",
            listOf(did),
            handle.contextId(),
            did,
            null
        )
        val summary = JSON.parseToJsonElement(scp.mcpContextEvents(handle)).jsonObject
        val ceRoot = summary["merkle_root"]?.jsonPrimitive?.content
        val ceCount = summary["event_count"]?.jsonPrimitive?.longOrNull
        buildJsonObject {
            put("event_count", JsonPrimitive(ceCount ?: -1L))
            put("root_matches_authoritative", JsonPrimitive(ceRoot == authRoot))
            put("count_matches_authoritative", JsonPrimitive(ceCount == authCount))
        }
    }

// Fixed 32-byte nonce used when `signed_at_override` pins the SCPID
// response. Must match
// `bindings/python/tests/bridge_parity/seed_operations.py::PARITY_NONCE_HEX`.
private const val PARITY_NONCE_HEX =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// Year-2286 timestamp — far enough in the future that wall-clock expiry
// cannot trip the SCPID expiry check. Must match the Python harness's
// `PARITY_CHALLENGE_EXPIRES_AT_MS`.
private const val PARITY_CHALLENGE_EXPIRES_AT_MS = 9_999_999_999_000L

/**
 * When `signed_at_override` is supplied, REPLACE the bridge-issued
 * challenge with a pinned fixture so every bridge feeds `scpidSign` the
 * same canonical hash inputs. Mirrors
 * `node_bridge_runner.ts::patchChallengeForOverride`.
 */
private fun patchChallengeForOverride(
    challengeJson: String,
    signedAtOverride: Long?
): String {
    if (signedAtOverride == null) return challengeJson
    val pinned = buildJsonObject {
        put("protocol", JsonPrimitive("scpid/1.0"))
        put("nonce", JsonPrimitive(PARITY_NONCE_HEX))
        put("audience", JsonPrimitive("https://parity-test.example.com"))
        put("issued_at", JsonPrimitive(signedAtOverride))
        put("expires_at", JsonPrimitive(PARITY_CHALLENGE_EXPIRES_AT_MS))
    }
    return JSON.encodeToString(JsonElement.serializer(), pinned)
}

private suspend fun opSignMessage(args: JsonObject): JsonObject =
    uniffi.scp.Scp.withStorage(uniffi.scp.StorageConfig.InMemory).use { scp ->
        val audience = args["audience"]?.jsonPrimitive?.content
            ?: "https://parity-test.example.com"
        val ttl = args["ttl_seconds"]?.jsonPrimitive?.longOrNull?.toULong() ?: 60uL
        val seed = args["seed_hex"]?.jsonPrimitive?.content?.let { seedFromHex(it) }
        val signedAtOverride = args["signed_at_override"]?.jsonPrimitive?.longOrNull
        val identity = scp.identityCreate("in_memory", seed)
        // `scpidChallenge` is a stateless helper — remains a free function
        // in `uniffi.scp`.
        val challenge = uniffi.scp.scpidChallenge(audience, ttl)
        val patched = patchChallengeForOverride(challenge, signedAtOverride)
        val responseJson = scp.scpidSign(
            identity,
            "#active",
            patched,
            signedAtOverride?.toULong()
        )
        val parsed = JSON.parseToJsonElement(responseJson).jsonObject
        buildJsonObject {
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
            "outlet_register" -> opOutletRegister(req.args)
            "ucan_mint" -> opUcanMint(req.args)
            "ucan_validate_malformed" -> opUcanValidateMalformed(req.args)
            "ucan_evaluate_malformed" -> opUcanEvaluateMalformed(req.args)
            "ucan_evaluate_structured" -> opUcanEvaluateStructured(req.args)
            "transport_status" -> opTransportStatus(req.args)
            "event_log_query_filtered" -> opEventLogQueryFiltered(req.args)
            "event_log_verify_inclusion" -> opEventLogVerifyInclusion(req.args)
            "event_log_absence_of_lifecycle_event_rejected" ->
                opEventLogAbsenceRejected(req.args)
            "event_log_absence_over_divergent_local_tree_rejected" ->
                opEventLogAbsenceOverDivergentLocalTree(req.args)
            "event_log_verify_malformed_claim_rejected" ->
                opEventLogVerifyMalformedClaim(req.args)
            "mcp_context_events_authoritative" ->
                opMcpContextEventsAuthoritative(req.args)
            "unregistered_did_rejected" -> opUnregisteredDidRejected(req.args)
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
                    // Per-op `Scp()` instances mean there are no module-level
                    // runner caches to clear. Respond ok for harness parity.
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
