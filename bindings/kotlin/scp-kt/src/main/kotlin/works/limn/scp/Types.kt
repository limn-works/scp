// Types.kt — Kotlin SDK typed enums for stringly-typed parameters (M5)
//
// Provides type-safe enum classes for custody type, bridge mode, and
// shadow status parameters that were previously raw strings. Each enum
// has a rawValue matching the wire format expected by the FFI bridge.
//
// Provenance: §3.2 (Key Custody), §12.2 (Bridge Connectors), ADR-023

package works.limn.scp

import java.text.Normalizer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import works.limn.scp.bridge.BridgeException

/**
 * Key custody method for identity key management (spec section 3.2).
 *
 * Determines where cryptographic keys are stored and managed. The
 * [rawValue] property returns the string expected by the FFI bridge.
 *
 * @property rawValue Wire-format string passed to the FFI bridge.
 */
/**
 * Canonical protocol capability strings and parameterised constructors.
 *
 * These are the SDK-facing colon-separated forms accepted by `Capability::new`
 * in Rust (e.g. `"messages:write"`, `"outlet:call:*"`) — the shape used in
 * context ceilings, role capability lists, and UCAN capability arrays.
 * Parameterised capabilities are plain strings built by [outletQuery] and
 * [outletCall].
 *
 * The pre-rename tool-prefixed stems (invoke / register / interface) are
 * deleted with no transitional alias; the protocol hard-rejects them at
 * construction time (ADR-049 §1).
 */
object Capability {
    const val MESSAGES_READ = "messages:read"
    const val MESSAGES_WRITE = "messages:write"

    /** Query outlet capability — read-only; never billed. */
    const val OUTLET_QUERY_ALL = "outlet:query:*"

    /** Action outlet capability — the outlet may mutate state and may incur cost (billable). */
    const val OUTLET_CALL_ALL = "outlet:call:*"
    const val OUTLET_REGISTER = "outlet:register"
    const val MEMBER_INVITE = "member:invite"
    const val MEMBER_REMOVE = "member:remove"
    const val ROLE_ASSIGN = "role:assign"
    const val GOVERNANCE_PROPOSE = "governance:propose"
    const val GOVERNANCE_VOTE = "governance:vote"
    const val CONTEXT_CLOSE = "context:close"
    const val CHILD_CONTEXT_CREATE = "context:child:create"
    const val OUTLET_INTERFACE = "outlet:interface"
    const val BRIDGING = "bridging"
    const val MEDIA_VOICE = "media:voice"
    const val MEDIA_VIDEO = "media:video"
    const val MEDIA_SCREEN_SHARE = "media:screen_share"
    const val MEMBER_BAN = "member:ban"
    const val METADATA_EDIT = "metadata:edit"

    /**
     * Builds the capability string for invoking a specific Query (read-only)
     * outlet. Query outlet capability — read-only; never billed.
     * Per spec §5.4.2.1 the [outletId] suffix must match
     * `^[a-z0-9_-]{1,128}$`.
     */
    fun outletQuery(outletId: String): String = "outlet:query:$outletId"

    /**
     * Builds the capability string for invoking a specific Action (mutating)
     * outlet. Action outlet capability — the outlet may mutate state and may
     * incur cost (billable). Per spec §5.4.2.1 the [outletId] suffix must
     * match `^[a-z0-9_-]{1,128}$`.
     */
    fun outletCall(outletId: String): String = "outlet:call:$outletId"
}

enum class CustodyType(val rawValue: String) {
    /**
     * Platform-native secure storage (Keychain on macOS/iOS, Keystore
     * on Android, credential manager on Windows/Linux). Default.
     */
    PLATFORM("platform"),

    /**
     * Ephemeral in-memory key store, suitable for testing or
     * short-lived agents. Keys are lost on process exit.
     */
    IN_MEMORY("in_memory"),

    /**
     * Software-backed file-based key store with passphrase protection.
     */
    SOFTWARE("software"),
    ;

    companion object {
        /**
         * Parse a raw string into a [CustodyType], or null if unrecognized.
         */
        fun fromRawValue(value: String): CustodyType? = entries.find { it.rawValue == value }
    }
}

/**
 * Bridge operating mode (spec section 12.2).
 *
 * Determines how a bridge connector relays messages between an external
 * platform and an SCP context. The [rawValue] property returns the
 * string expected by the FFI bridge.
 *
 * @property rawValue Wire-format string passed to the FFI bridge.
 */
enum class BridgeMode(val rawValue: String) {
    /** Messages forwarded verbatim. Bridge is a transparent pipe. */
    RELAY("relay"),

    /**
     * Bridge controls external-side identity and can act on behalf
     * of participants.
     */
    PUPPET("puppet"),

    /** Bridge exposes a programmatic API rather than a chat interface. */
    API("api"),

    /** Both SCP and external participants have equal agency. */
    COOPERATIVE("cooperative"),
    ;

    companion object {
        /**
         * Parse a raw string into a [BridgeMode], or null if unrecognized.
         */
        fun fromRawValue(value: String): BridgeMode? = entries.find { it.rawValue == value }
    }
}

/**
 * Shadow identity provenance status (spec section 12.2).
 *
 * Indicates how a bridged participant's identity was established.
 * Used for trust evaluation. The [rawValue] property returns the
 * string expected by the FFI bridge.
 *
 * @property rawValue Wire-format string passed to the FFI bridge.
 */
enum class ShadowStatus(val rawValue: String) {
    /** Identity is a shadow -- no verified link to external identity. */
    SHADOW("shadow"),

    /** External participant has completed identity claim verification. */
    CLAIMED("claimed"),
    ;

    companion object {
        /**
         * Parse a raw string into a [ShadowStatus], or null if unrecognized.
         */
        fun fromRawValue(value: String): ShadowStatus? = entries.find { it.rawValue == value }
    }
}

// ---------------------------------------------------------------------------
// Outlet definitions (spec §5.4.1, ADR-010)
// ---------------------------------------------------------------------------

/**
 * Per-invocation cost metadata for an outlet (spec section 5.4.1).
 *
 * All monetary values are in the smallest currency unit (e.g., cents
 * for USD, satoshis for BTC).
 *
 * @property amount Cost per invocation in the smallest currency unit. A [ULong]
 *     so the full unsigned smallest-unit range round-trips exactly (ADR-060
 *     native-integer money surface); unsigned by construction — a monetary
 *     amount is never negative.
 * @property currency ISO 4217 or protocol-defined currency code.
 * @property payee DID of the payment recipient. May differ from the outlet operator.
 * @property costFormula Optional pricing formula identifier for dynamic pricing (spec section 19.4).
 */
data class OutletCost(
    val amount: ULong,
    val currency: String,
    val payee: String,
    val costFormula: String? = null,
)

/**
 * Definition of an outlet that can be registered in an SCP context.
 *
 * Provides a typed Kotlin data class for constructing outlet definitions
 * that are serialized to JSON for the FFI bridge layer.
 *
 * See ADR-010 (Outlet Registry) and spec section 5.4.1.
 *
 * @property name Human-readable outlet name.
 * @property description Outlet description.
 * @property inputSchemaJson JSON Schema for outlet input (as a JSON string).
 * @property outputSchemaJson JSON Schema for outlet output (as a JSON string).
 * @property operatorDid DID of the outlet operator (responsible party).
 * @property testVectorsJson Test vectors for integrity verification (serialized as JSON string).
 * @property implementationHashHex SHA-256 hash of the implementation binary as hex string.
 * @property cost Optional per-invocation cost metadata (spec section 5.4.1).
 */
data class OutletDefinition(
    val name: String,
    val description: String,
    val inputSchemaJson: String,
    val outputSchemaJson: String,
    val operatorDid: String,
    val testVectorsJson: String? = null,
    val implementationHashHex: String? = null,
    val cost: OutletCost? = null,
) {
    /**
     * Serializes this definition to a JSON string suitable for the FFI bridge.
     *
     * Uses [buildJsonObject] from kotlinx.serialization to produce structurally
     * valid JSON, preventing injection via untrusted string fields.
     */
    fun toJson(): String =
        Json.encodeToString(
            buildJsonObject {
                put("name", name)
                put("description", description)
                put("input_schema_json", Json.parseToJsonElement(inputSchemaJson))
                put("output_schema_json", Json.parseToJsonElement(outputSchemaJson))
                put("operator_did", operatorDid)
                if (testVectorsJson != null) {
                    put("test_vectors_json", Json.parseToJsonElement(testVectorsJson))
                }
                if (implementationHashHex != null) {
                    put("implementation_hash", implementationHashHex)
                }
                if (cost != null) {
                    putJsonObject("cost") {
                        // ADR-060: a monetary Amount crosses JSON as its canonical
                        // base-10 decimal string (never a bare number), so the full
                        // ULong range survives exactly.
                        put("amount", cost.amount.toString())
                        put("currency", cost.currency)
                        put("payee", cost.payee)
                        if (cost.costFormula != null) {
                            put("cost_formula", cost.costFormula)
                        }
                    }
                }
            },
        )
}

// ---------------------------------------------------------------------------
// App Sandboxing (spec §8.4.1, §8.4.2, issue #595)
// ---------------------------------------------------------------------------

/**
 * Result of validating a capability declaration.
 *
 * See spec sections 8.4.1 and 8.4.2.
 */
data class DeclarationValidationResult(
    /** Whether the validation passed. */
    val valid: Boolean,
    /** Capabilities granted to the app (if valid). */
    val grantedCapabilities: List<String>,
    /** Error message if validation failed, null otherwise. */
    val error: String?,
    /** The DID of the app from the declaration. */
    val appDid: String,
)

/**
 * Capability-restricted context handle (spec §8.4.2).
 *
 * Wraps a context with a whitelist of allowed capabilities. All protocol
 * operations must check the whitelist before proceeding. An app cannot access
 * protocol operations beyond its declared capabilities.
 *
 * Once created, a [ScopedHandle] cannot gain additional capabilities
 * (no escalation guarantee, spec 8.4.2 rule 4).
 *
 * This is intentionally NOT a data class: the auto-generated `copy()` method
 * on data classes would allow callers to create a new handle with escalated
 * capabilities, bypassing the no-escalation guarantee.
 */
class ScopedHandle internal constructor(
    /** The context ID this handle is scoped to. */
    val contextId: String,
    grantedCapabilities: List<String>,
    /** The DID of the app. */
    val appDid: String,
) {
    /** The capabilities granted to this app binding (immutable). */
    val grantedCapabilities: List<String> = grantedCapabilities.toList()

    /**
     * Check whether a given capability is allowed.
     */
    fun hasCapability(capability: String): Boolean {
        if (grantedCapabilities.contains(capability)) return true
        // OutletCallAll covers any specific OutletCall.
        if (capability.startsWith("outlet:call:") &&
            capability != "outlet:call:*" &&
            grantedCapabilities.contains("outlet:call:*")
        ) {
            return true
        }
        // OutletQueryAll covers any specific OutletQuery.
        if (capability.startsWith("outlet:query:") &&
            capability != "outlet:query:*" &&
            grantedCapabilities.contains("outlet:query:*")
        ) {
            return true
        }
        return false
    }

    /**
     * Throws [BridgeException] if the capability is not granted.
     */
    fun checkCapability(capability: String) {
        if (!hasCapability(capability)) {
            throw BridgeException(
                "capability denied: $capability not granted to app $appDid",
                "SCP-CTX-2050",
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ScopedHandle) return false
        return contextId == other.contextId &&
            grantedCapabilities == other.grantedCapabilities &&
            appDid == other.appDid
    }

    override fun hashCode(): Int {
        var result = contextId.hashCode()
        result = 31 * result + grantedCapabilities.hashCode()
        result = 31 * result + appDid.hashCode()
        return result
    }

    override fun toString(): String =
        "ScopedHandle(contextId=$contextId, appDid=$appDid, " +
            "capabilities=${grantedCapabilities.size})"
}

// ---------------------------------------------------------------------------
// Broadcast Site Configuration (SCP-293, spec §18.11.12)
// ---------------------------------------------------------------------------

/**
 * Node-local site configuration for broadcast projection (spec section 18.11.12).
 *
 * Passed to `enableSiteProjection` to configure path-based HTTP serving of
 * broadcast content. NOT part of governance -- deployment concern only.
 *
 * Mirrors `scp_node::projection::SiteConfig`.
 *
 * Construction validates [hostname], [deployRetentionCount], and [cspOverride].
 *
 * @property hostname Virtual host hostname (e.g., `"mysite.example.com"`). RFC 1123 validated.
 * @property indexPath Default path for directory requests (default: `"/index.html"`).
 * @property maxAssetsPerDeploy Maximum assets per deploy (default: 10,000).
 * @property maxDeploySizeBytes Maximum total deploy size in bytes (default: 536,870,912 = 512 MiB).
 * @property deployRetentionCount Number of deploys to retain (default: 2, max 8).
 * @property cspOverride Optional CSP override. Validated: no `unsafe-eval`, `unsafe-inline`,
 *   `unsafe-hashes`, bare `*`, `data:`, `blob:`.
 */
/**
 * Node-local site configuration for broadcast projection (spec section 18.11.12).
 *
 * This is intentionally NOT a data class: the auto-generated `copy()` method
 * on data classes would allow callers to create a new instance that bypasses
 * init validation (e.g., invalid hostname, out-of-range deployRetentionCount).
 *
 * Custom [equals], [hashCode], and [toString] are provided for testing ergonomics.
 */
class SiteConfig(
    val hostname: String,
    val indexPath: String = "/index.html",
    val maxAssetsPerDeploy: Int = 10_000,
    val maxDeploySizeBytes: Long = 536_870_912L,
    val deployRetentionCount: Int = 2,
    val cspOverride: String? = null,
) {
    init {
        validateHostname(hostname)
        require(maxAssetsPerDeploy >= 1) { "maxAssetsPerDeploy must be >= 1" }
        require(maxDeploySizeBytes >= 1) { "maxDeploySizeBytes must be >= 1" }
        require(deployRetentionCount in 1..8) {
            "deployRetentionCount must be between 1 and 8, got $deployRetentionCount"
        }
        if (cspOverride != null) {
            validateCsp(cspOverride)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SiteConfig) return false
        return hostname == other.hostname &&
            indexPath == other.indexPath &&
            maxAssetsPerDeploy == other.maxAssetsPerDeploy &&
            maxDeploySizeBytes == other.maxDeploySizeBytes &&
            deployRetentionCount == other.deployRetentionCount &&
            cspOverride == other.cspOverride
    }

    override fun hashCode(): Int {
        var result = hostname.hashCode()
        result = 31 * result + indexPath.hashCode()
        result = 31 * result + maxAssetsPerDeploy
        result = 31 * result + maxDeploySizeBytes.hashCode()
        result = 31 * result + deployRetentionCount
        result = 31 * result + (cspOverride?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String =
        "SiteConfig(hostname=$hostname, indexPath=$indexPath, " +
            "maxAssetsPerDeploy=$maxAssetsPerDeploy, maxDeploySizeBytes=$maxDeploySizeBytes, " +
            "deployRetentionCount=$deployRetentionCount, cspOverride=$cspOverride)"

    companion object {
        private val HOSTNAME_LABEL_REGEX = Regex("^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\$")
        private val FORBIDDEN_CSP_KEYWORDS = listOf("unsafe-eval", "unsafe-inline", "unsafe-hashes")

        /**
         * Validates a hostname per RFC 1123.
         *
         * @throws IllegalArgumentException if the hostname is invalid.
         */
        fun validateHostname(hostname: String) {
            require(hostname.isNotEmpty()) { "hostname must not be empty" }
            require(hostname.length <= 253) { "hostname exceeds 253 characters" }
            for (label in hostname.split(".")) {
                require(label.isNotEmpty() && label.length <= 63) {
                    "invalid hostname label: '$label'"
                }
                require(HOSTNAME_LABEL_REGEX.matches(label)) {
                    "hostname label contains invalid characters: '$label'"
                }
            }
        }

        /**
         * Validates a CSP override string.
         *
         * Rejects `unsafe-eval`, `unsafe-inline`, `unsafe-hashes`, bare `*`,
         * `data:`, and `blob:` as sources.
         *
         * @throws IllegalArgumentException if the CSP is invalid.
         */
        fun validateCsp(csp: String) {
            val lower = csp.lowercase()
            for (keyword in FORBIDDEN_CSP_KEYWORDS) {
                require(!lower.contains(keyword)) {
                    "CSP must not contain '$keyword'"
                }
            }
            for (token in lower.split("\\s+".toRegex())) {
                require(token != "*") { "CSP must not contain bare wildcard '*'" }
                require(token != "data:") { "CSP must not contain 'data:' source" }
                require(token != "blob:") { "CSP must not contain 'blob:' source" }
            }
        }
    }

    /**
     * Serializes this configuration to a JSON string suitable for the FFI bridge.
     *
     * Uses [buildJsonObject] from kotlinx.serialization to produce structurally
     * valid JSON, preventing injection via untrusted string fields.
     */
    fun toJson(): String = Json.encodeToString(
        buildJsonObject {
            put("hostname", hostname)
            put("index_path", indexPath)
            put("max_assets_per_deploy", maxAssetsPerDeploy)
            put("max_deploy_size_bytes", maxDeploySizeBytes)
            put("deploy_retention_count", deployRetentionCount)
            if (cspOverride != null) {
                put("csp_override", cspOverride)
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Broadcast Asset Publishing (SCP-290, ADR-035)
// ---------------------------------------------------------------------------

/**
 * An asset to publish to a broadcast context (SCP-290).
 *
 * Typed data class matching the Rust `AssetEntry` UniFFI record. Prevents
 * positional transposition of path/content_type/body.
 *
 * Custom [equals] and [hashCode] are required because [body] is a [ByteArray],
 * which does not implement structural equality by default in Kotlin.
 *
 * @property path Validated URL path (e.g., `/index.html`, `/styles.css`).
 * @property contentType Validated MIME type (e.g., `text/html`, `text/css`).
 * @property body Raw content bytes.
 */
class AssetEntry(
    val path: String,
    val contentType: String,
    val body: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AssetEntry) return false
        return path == other.path &&
            contentType == other.contentType &&
            body.contentEquals(other.body)
    }

    override fun hashCode(): Int {
        var result = path.hashCode()
        result = 31 * result + contentType.hashCode()
        result = 31 * result + body.contentHashCode()
        return result
    }

    override fun toString(): String = "AssetEntry(path=$path, contentType=$contentType, bodySize=${body.size})"
}

/**
 * Result of publishing an asset to a broadcast context (SCP-290, SCP-292).
 *
 * @property blobId Hex-encoded SHA-256 of the serialized broadcast envelope.
 * @property etag Hex-encoded SHA-256 of the asset body.
 * @property deployId The deploy ID for this asset (auto-generated or caller-provided).
 */
data class PublishResult(
    val blobId: String,
    val etag: String,
    val deployId: String,
)

/**
 * Result of publishing multiple assets to a broadcast context (SCP-292).
 *
 * @property results Per-asset publish results.
 * @property deployId The shared deploy ID for this batch.
 */
data class BatchPublishResult(
    val results: List<PublishResult>,
    val deployId: String,
)

// ---------------------------------------------------------------------------
// TestVector (spec §7.3.3, ADR-010)
// ---------------------------------------------------------------------------

/**
 * A known input-output pair for outlet conformance testing.
 *
 * Mirrors `scp_core::context::outlets::TestVector`. Any agent can invoke a
 * outlet with test vector inputs and verify the output matches the expected
 * result.
 *
 * Provenance: spec §7.3.3, ADR-010 (phase-2)
 *
 * @property description Human-readable description of what this test vector validates.
 * @property input The serialized input value (JSON string).
 * @property expectedOutput The expected serialized output value (JSON string).
 */
data class TestVector(
    val description: String,
    val input: String,
    val expectedOutput: String,
)

// ---------------------------------------------------------------------------
// Projection Parameter Validation (SCP-296 post-merge audit)
// ---------------------------------------------------------------------------

private val HEX_64_REGEX = Regex("^[0-9a-fA-F]{64}\$")

/**
 * Validates an admission policy string before FFI.
 *
 * Accepts both casings (`"open"`/`"Open"`, `"gated"`/`"Gated"`) because
 * the Rust bridge normalizes via `.to_lowercase()`.
 *
 * @param admission The admission policy string.
 * @throws IllegalArgumentException if admission is not valid.
 */
fun validateAdmission(admission: String) {
    val lower = admission.lowercase()
    require(lower == "open" || lower == "gated") {
        "admission must be \"open\" or \"gated\" (case-insensitive), got \"$admission\""
    }
}

/**
 * Validates a broadcast key hex string before FFI.
 *
 * Must be exactly 64 hex characters (32 bytes AES-256 key).
 *
 * @param broadcastKeyHex Hex-encoded 32-byte broadcast key.
 * @throws IllegalArgumentException if the string is not valid.
 */
fun validateBroadcastKeyHex(broadcastKeyHex: String) {
    require(HEX_64_REGEX.matches(broadcastKeyHex)) {
        "broadcastKeyHex must be exactly 64 hex characters (32 bytes)"
    }
}

// ---------------------------------------------------------------------------
// Client-side Validation (SCP-297, spec §18.11.9)
// ---------------------------------------------------------------------------

/** Maximum content path length in bytes. */
private const val MAX_CONTENT_PATH_BYTES = 1024

/** Maximum deploy ID length in bytes. */
private const val MAX_DEPLOY_ID_BYTES = 128

/** Allowed deploy ID character regex: ASCII alphanumeric plus `-` and `_`. */
private val DEPLOY_ID_REGEX = Regex("^[a-zA-Z0-9\\-_]+$")

/** RFC 7230 section 3.2.6 tchar regex (minus `%`). */
private val TCHAR_REGEX = Regex("^[a-zA-Z0-9!#\$&'*+\\-.^_`|~]+$")

/**
 * Returns true for Unicode formatting and invisible characters that should
 * be rejected in content paths. Mirrors the Rust `is_unicode_formatting` helper.
 */
private fun isUnicodeFormatting(cp: Int): Boolean = cp in 0x00A0..0x00A0 || // NBSP
    cp in 0x1680..0x1680 || // Ogham space mark
    cp in 0x2000..0x200F || // Typographic spaces (U+2000-U+200A) + ZWSP..RLM (U+200B-U+200F)
    cp in 0x2028..0x2029 || // Line/paragraph separators
    cp in 0x202A..0x202F || // Bidi embedding controls + narrow no-break space
    cp == 0x205F || // Medium mathematical space
    cp in 0x2060..0x206F || // Word joiner, invisible operators
    cp == 0x3000 || // Ideographic space
    cp == 0xFEFF || // BOM / ZWNBSP
    cp in 0xFFFE..0xFFFF // Non-characters

/** Forbidden substrings in content paths, paired with error messages. */
private val CONTENT_PATH_FORBIDDEN = listOf(
    "\\" to "ContentPath must not contain backslashes",
    "%" to "ContentPath must not contain percent-encoded bytes",
    "?" to "ContentPath must not contain query strings ('?')",
    "#" to "ContentPath must not contain fragments ('#')",
    "\u0000" to "ContentPath must not contain null bytes",
    "//" to "ContentPath must not contain '//'",
)

/** Checks for forbidden substrings and control characters in a content path. */
private fun contentPathCharError(path: String): String? {
    val substringErr = CONTENT_PATH_FORBIDDEN.firstOrNull { path.contains(it.first) }?.second
    if (substringErr != null) return substringErr
    // C0 controls (U+0000-U+001F), DEL (U+007F), and C1 controls (U+0080-U+009F)
    val ctrlChar = path.firstOrNull { it.code in 0x00..0x1F || it.code == 0x7F || it.code in 0x80..0x9F }
    if (ctrlChar != null) {
        return "ContentPath must not contain control character U+${"%04X".format(ctrlChar.code)}"
    }
    // Non-ASCII whitespace, bidi, and formatting characters
    val fmtChar = path.firstOrNull { it.code > 0x7F && isUnicodeFormatting(it.code) }
    return fmtChar?.let {
        "ContentPath must not contain non-ASCII whitespace/formatting U+${"%04X".format(it.code)}"
    }
}

/** Checks structural rules (prefix, length, trailing slash, segments). */
private fun contentPathStructureError(path: String): String? = when {
    !path.startsWith("/") -> "ContentPath must start with '/'"
    path.toByteArray(Charsets.UTF_8).size > MAX_CONTENT_PATH_BYTES ->
        "ContentPath exceeds $MAX_CONTENT_PATH_BYTES bytes"
    path.length > 1 && path.endsWith("/") -> "ContentPath must not have trailing slash (except root '/')"
    else -> path.split("/").drop(1).firstNotNullOfOrNull { segment ->
        when (segment) {
            "." -> "ContentPath must not contain '.' segments"
            ".." -> "ContentPath must not contain '..' segments (directory traversal)"
            else -> null
        }
    }
}

/**
 * Validates a content path before FFI crossing (SCP-297).
 *
 * Mirrors the Rust `ContentPath::new` validation from
 * `crates/scp-core/src/context/broadcast_content.rs`.
 *
 * @param path The content path to validate.
 * @throws BridgeException if the path is invalid.
 */
fun validateContentPath(path: String) {
    // NFC-normalize before validation
    val normalized = Normalizer.normalize(path, Normalizer.Form.NFC)
    val error = contentPathStructureError(normalized) ?: contentPathCharError(normalized)
    if (error != null) throw BridgeException(error, "SCP-VALID-7010")
}

/** Checks for control characters in a MIME type string. */
private fun mimeTypeControlCharError(contentType: String): String? {
    // C0 controls (U+0000-U+001F), DEL (U+007F), and C1 controls (U+0080-U+009F)
    val ctrlChar = contentType.firstOrNull { it.code <= 0x1F || it.code == 0x7F || it.code in 0x80..0x9F }
    return ctrlChar?.let { "MimeType must not contain control character U+${"%04X".format(it.code)}" }
}

/**
 * Checks MIME type structure (semicolon, slash count, non-empty parts)
 * and RFC 7230 tchar validation.
 */
private fun mimeTypeStructureError(contentType: String): String? = when {
    contentType.isEmpty() -> "MimeType must not be empty"
    contentType.contains(";") -> "MimeType must not contain parameters (';' not allowed)"
    contentType.count { it == '/' } != 1 -> "MimeType must be 'type/subtype' (exactly one '/')"
    else -> {
        val parts = contentType.split("/", limit = 2)
        if (parts.size != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            "MimeType type and subtype must both be non-empty"
        } else if (!TCHAR_REGEX.matches(parts[0])) {
            "MimeType type part contains invalid characters"
        } else if (!TCHAR_REGEX.matches(parts[1])) {
            "MimeType subtype part contains invalid characters"
        } else {
            null
        }
    }
}

/**
 * Validates a MIME type before FFI crossing (SCP-297).
 *
 * Mirrors the Rust `MimeType::new` validation from
 * `crates/scp-core/src/context/broadcast_content.rs`.
 *
 * @param contentType The MIME type to validate.
 * @throws BridgeException if the MIME type is invalid.
 */
fun validateMimeType(contentType: String) {
    // Control char check before structure — matches Rust validation order.
    val error = mimeTypeControlCharError(contentType) ?: mimeTypeStructureError(contentType)
    if (error != null) throw BridgeException(error, "SCP-VALID-7011")
}

/** Returns an error message if the deploy ID is invalid, null otherwise. */
private fun deployIdError(deployId: String): String? = when {
    deployId.isEmpty() -> "deploy_id must not be empty"
    deployId.toByteArray(Charsets.UTF_8).size > MAX_DEPLOY_ID_BYTES ->
        "deploy_id exceeds $MAX_DEPLOY_ID_BYTES bytes"
    !DEPLOY_ID_REGEX.matches(deployId) ->
        "deploy_id must be ASCII alphanumeric, '-', or '_'"
    else -> null
}

/**
 * Validates a deploy ID before FFI crossing (SCP-297).
 *
 * Mirrors the Rust `validate_deploy_id` from
 * `crates/scp-core/src/context/broadcast_content.rs`.
 *
 * @param deployId The deploy ID to validate.
 * @throws BridgeException if the deploy ID is invalid.
 */
fun validateDeployId(deployId: String) {
    deployIdError(deployId)?.let { throw BridgeException(it, "SCP-VALID-7012") }
}
