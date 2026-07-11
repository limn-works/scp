// ConsequenceRule.kt — Typed Kotlin SDK shapes for ADR-017 consequence rules.
//
// Mirrors `scp_protocol::trust::consequence::{ConsequenceRule, ConsequenceTrigger,
// ConsequenceAction, EnforcementSeverity}` and `scp_protocol::context::params::
// ConsequenceConfig`. The SDK exposes typed sealed hierarchies (no stringly-typed
// JSON) and serializes to the Rust serde wire format at the bridge boundary.
//
// Provenance: ADR-017 (Trust Engine), §9.3 (Consequence Rules), #1531

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

// ---------------------------------------------------------------------------
// ConsequenceTrigger
// ---------------------------------------------------------------------------

/**
 * The condition that triggers a consequence rule.
 *
 * Mirrors `scp_protocol::trust::consequence::ConsequenceTrigger`. Each variant
 * counts events of a specific kind from the context's event log within the
 * rule's time window.
 *
 * The variant names are pinned in [CONSEQUENCE_TRIGGER_VARIANT_NAMES] so
 * accidental renames trip a compile error in the round-trip tests.
 */
sealed class ConsequenceTrigger {
    /** Rate of [scp_event_log::EventType::MessageSent] events for the subject. */
    data object MessageVelocity : ConsequenceTrigger()

    /** Rate of [scp_event_log::EventType::OutletInvoked] events for the subject. */
    data object OutletRateExceeded : ConsequenceTrigger()

    /** Count of governance actions targeting the subject. */
    data object WarningCount : ConsequenceTrigger()

    /**
     * A custom trigger keyed by string.
     *
     * @property key Trigger key — must be 1-256 bytes, no control or
     *   HTML-special characters. Validated by the bridge.
     */
    data class Custom(val key: String) : ConsequenceTrigger() {
        init {
            require(key.isNotEmpty()) { "Custom trigger key must not be empty" }
            require(key.length <= 256) {
                "Custom trigger key exceeds max length 256 (got ${key.length})"
            }
        }
    }
}

/**
 * Frozen list of [ConsequenceTrigger] variant short names. Used by tests to
 * pin the discriminated-union surface — renaming a variant trips the test.
 */
val CONSEQUENCE_TRIGGER_VARIANT_NAMES: List<String> = listOf(
    "MessageVelocity",
    "OutletRateExceeded",
    "WarningCount",
    "Custom",
)

// ---------------------------------------------------------------------------
// AccessScope
// ---------------------------------------------------------------------------

/**
 * Read/Write/Both scope for [EnforcementSeverity.RevokeAccess].
 *
 * Mirrors `scp_protocol::context::governance::AccessScope`.
 */
enum class AccessScope(val rawValue: String) {
    READ("Read"),
    WRITE("Write"),
    BOTH("Both"),
}

// ---------------------------------------------------------------------------
// ConsequenceCapability — typed shape for SuspendCapability payload
// ---------------------------------------------------------------------------

/**
 * A capability that may be referenced inside [EnforcementSeverity.SuspendCapability].
 *
 * Mirrors `scp_protocol::context::roles::Capability`. The unit variants are
 * enumerated as [Unit]; payload-bearing variants ([OutletCall], [Custom]) carry
 * their string field directly.
 */
sealed class ConsequenceCapability {
    /**
     * A unit-variant capability (no payload). The [name] must match a
     * [Capability] enum variant name from the Rust protocol crate exactly,
     * e.g. `MessagesRead`, `MessagesWrite`, `GovernanceVote`.
     */
    data class Unit(val name: String) : ConsequenceCapability() {
        init {
            require(name.isNotEmpty()) { "Capability variant name must not be empty" }
        }
    }

    /**
     * Action-outlet invocation capability for a specific registered outlet.
     *
     * Mirrors `Capability::OutletCall(OutletId)`. Serializes as
     * `{"OutletCall": "<id>"}` to match the Rust newtype.
     */
    data class OutletCall(val outletId: String) : ConsequenceCapability() {
        init { require(outletId.isNotEmpty()) { "OutletCall outlet id must not be empty" } }
    }

    /**
     * Context-specific custom capability.
     *
     * Serializes as `{"Custom": "<name>"}` to match the Rust newtype.
     */
    data class Custom(val name: String) : ConsequenceCapability() {
        init { require(name.isNotEmpty()) { "Custom capability name must not be empty" } }
    }
}

// ---------------------------------------------------------------------------
// EnforcementSeverity
// ---------------------------------------------------------------------------

/**
 * Unified enforcement severity for consequence rules and governance actions.
 *
 * Mirrors `scp_protocol::trust::consequence::EnforcementSeverity`. Four tiers
 * ordered from least to most severe:
 *
 * 1. [SuspendCapability] — application-level block on a specific capability set.
 * 2. [SuspendAccess] — application-level block on the member's full capability set.
 * 3. [RevokeAccess] — cryptographic revocation (forward-only). Only allowed in
 *    consequence rules when [ConsequenceConfig.allowAutomaticAccessRevocation]
 *    is `true`.
 * 4. [RemoveMember] — MLS group ejection. Never allowed in consequence rules
 *    (governance-only).
 *
 * The variant names are pinned in [ENFORCEMENT_SEVERITY_VARIANT_NAMES].
 */
sealed class EnforcementSeverity {
    /** Suspend specific capabilities for the subject (application-level enforcement). */
    data class SuspendCapability(val capabilities: List<ConsequenceCapability>) : EnforcementSeverity() {
        init {
            require(capabilities.isNotEmpty()) {
                "SuspendCapability must list at least one capability"
            }
            require(capabilities.size <= MAX_SUSPEND_COUNT) {
                "SuspendCapability has ${capabilities.size} capabilities, max is $MAX_SUSPEND_COUNT"
            }
        }
    }

    /** Suspend ALL member capabilities (application-level enforcement). */
    data object SuspendAccess : EnforcementSeverity()

    /**
     * Cryptographic revocation — destroy the subject's access keys.
     *
     * Only allowed in a consequence rule when the parent [ConsequenceConfig]
     * sets [ConsequenceConfig.allowAutomaticAccessRevocation] to `true`.
     */
    data class RevokeAccess(val did: String, val access: AccessScope) : EnforcementSeverity() {
        init { require(did.isNotEmpty()) { "RevokeAccess.did must not be empty" } }
    }

    /**
     * MLS group ejection. **Never allowed in consequence rules** — present
     * here for parity with the Rust enum and reuse from typed governance
     * action helpers in the future.
     */
    data class RemoveMember(val did: String, val reason: String? = null) : EnforcementSeverity() {
        init { require(did.isNotEmpty()) { "RemoveMember.did must not be empty" } }
    }

    companion object {
        /** Mirror of `scp_protocol::trust::consequence::MAX_CAPABILITY_SUSPENSION_COUNT`. */
        const val MAX_SUSPEND_COUNT: Int = 32
    }
}

/** Frozen list of [EnforcementSeverity] variant short names. */
val ENFORCEMENT_SEVERITY_VARIANT_NAMES: List<String> = listOf(
    "SuspendCapability",
    "SuspendAccess",
    "RevokeAccess",
    "RemoveMember",
)

// ---------------------------------------------------------------------------
// ConsequenceAction
// ---------------------------------------------------------------------------

/**
 * The action taken when a [ConsequenceRule] fires.
 *
 * Mirrors `scp_protocol::trust::consequence::ConsequenceAction`.
 *
 * - [Enforcement] — apply an [EnforcementSeverity] tier to the subject.
 * - [AssignRole] — replace the subject's role.
 */
sealed class ConsequenceAction {
    /** Apply an enforcement severity to the subject. */
    data class Enforcement(val severity: EnforcementSeverity) : ConsequenceAction()

    /** Assign a role to the subject (replaces previous role). */
    data class AssignRole(val toRole: String) : ConsequenceAction() {
        init {
            require(toRole.isNotEmpty()) { "AssignRole.toRole must not be empty" }
            require(toRole.length <= 128) {
                "AssignRole.toRole exceeds max length 128 (got ${toRole.length})"
            }
        }
    }
}

/** Frozen list of [ConsequenceAction] variant short names. */
val CONSEQUENCE_ACTION_VARIANT_NAMES: List<String> = listOf("Enforcement", "AssignRole")

// ---------------------------------------------------------------------------
// ConsequenceRule
// ---------------------------------------------------------------------------

/**
 * A declared consequence rule (ADR-017 §1).
 *
 * Mirrors `scp_protocol::trust::consequence::ConsequenceRule`. Each rule
 * specifies a trigger condition, an enforcement action, a numeric threshold,
 * and a time window for counting events.
 *
 * Rules are visible to all participants before they join — the opt-in
 * contract for consequences. The SDK serializes the list to the wire JSON
 * shape via [encodeConsequenceRulesJson] before forwarding to the bridge.
 *
 * @property trigger Trigger condition.
 * @property action Enforcement action taken when the trigger fires.
 * @property threshold Threshold count: when matching events within the time
 *   window meet or exceed this value, the consequence fires. Must be > 0.
 * @property windowSecs Time window in seconds. Only events in
 *   `[now - windowSecs, now]` count.
 */
data class ConsequenceRule(
    val trigger: ConsequenceTrigger,
    val action: ConsequenceAction,
    val threshold: Long,
    val windowSecs: Long,
) {
    init {
        require(threshold > 0) { "ConsequenceRule.threshold must be > 0" }
        require(windowSecs >= 0) { "ConsequenceRule.windowSecs must be non-negative" }
    }
}

// ---------------------------------------------------------------------------
// ConsequenceConfig
// ---------------------------------------------------------------------------

/**
 * Per-context configuration governing which enforcement severities
 * consequence rules may reference (ADR-017, #1531).
 *
 * Mirrors `scp_protocol::context::params::ConsequenceConfig`. Defaults to
 * `allowAutomaticAccessRevocation = false`: contexts must explicitly opt in
 * to permit [EnforcementSeverity.RevokeAccess] in consequence rules.
 * [EnforcementSeverity.RemoveMember] is **never** allowed in consequence rules
 * regardless of this flag.
 *
 * @property allowAutomaticAccessRevocation If `true`, consequence rules may
 *   reference [EnforcementSeverity.RevokeAccess] — automatic cryptographic
 *   revocation of a member's access keys.
 */
data class ConsequenceConfig(
    val allowAutomaticAccessRevocation: Boolean = false,
)

// ---------------------------------------------------------------------------
// JSON encoding — typed shapes -> Rust serde wire format
// ---------------------------------------------------------------------------

/**
 * Encodes a typed [ConsequenceRule] list to the JSON wire shape expected by
 * the Rust bridge. Uses [kotlinx.serialization.json] structural builders so
 * the encoder cannot inject malformed JSON.
 *
 * Public for SDK call sites that need to forward pre-serialized rules
 * (e.g. invitation evaluation) and for tests.
 */
fun encodeConsequenceRulesJson(rules: List<ConsequenceRule>): String =
    Json.encodeToString(
        JsonArray.serializer(),
        buildJsonArray { rules.forEach { add(encodeConsequenceRuleElement(it)) } },
    )

/**
 * Encodes a typed [ConsequenceConfig] to the JSON wire shape expected by the
 * Rust bridge. Field names are snake_cased to match
 * `serde_json::to_string(&ConsequenceConfig)`.
 */
fun encodeConsequenceConfigJson(config: ConsequenceConfig): String =
    Json.encodeToString(
        JsonObject.serializer(),
        buildJsonObject {
            put("allow_automatic_access_revocation", config.allowAutomaticAccessRevocation)
        },
    )

private fun encodeConsequenceRuleElement(rule: ConsequenceRule): JsonObject =
    buildJsonObject {
        put("trigger", encodeTriggerElement(rule.trigger))
        put("action", encodeActionElement(rule.action))
        put("threshold", rule.threshold)
        putJsonObject("window") {
            put("secs", rule.windowSecs)
            put("nanos", 0)
        }
    }

private fun encodeTriggerElement(trigger: ConsequenceTrigger): JsonElement = when (trigger) {
    ConsequenceTrigger.MessageVelocity -> JsonPrimitive("MessageVelocity")
    ConsequenceTrigger.OutletRateExceeded -> JsonPrimitive("OutletRateExceeded")
    ConsequenceTrigger.WarningCount -> JsonPrimitive("WarningCount")
    is ConsequenceTrigger.Custom -> buildJsonObject { put("Custom", trigger.key) }
}

private fun encodeActionElement(action: ConsequenceAction): JsonElement = when (action) {
    is ConsequenceAction.Enforcement -> buildJsonObject {
        put("Enforcement", encodeSeverityElement(action.severity))
    }
    is ConsequenceAction.AssignRole -> buildJsonObject {
        putJsonObject("AssignRole") { put("to_role", action.toRole) }
    }
}

private fun encodeSeverityElement(severity: EnforcementSeverity): JsonElement = when (severity) {
    EnforcementSeverity.SuspendAccess -> JsonPrimitive("SuspendAccess")
    is EnforcementSeverity.SuspendCapability -> buildJsonObject {
        putJsonObject("SuspendCapability") {
            putJsonArray("capabilities") {
                severity.capabilities.forEach { add(encodeCapabilityElement(it)) }
            }
        }
    }
    is EnforcementSeverity.RevokeAccess -> buildJsonObject {
        putJsonObject("RevokeAccess") {
            put("did", severity.did)
            put("access", severity.access.rawValue)
        }
    }
    is EnforcementSeverity.RemoveMember -> buildJsonObject {
        putJsonObject("RemoveMember") {
            put("did", severity.did)
            put("reason", severity.reason?.let { JsonPrimitive(it) } ?: JsonNull)
        }
    }
}

private fun encodeCapabilityElement(capability: ConsequenceCapability): JsonElement = when (capability) {
    is ConsequenceCapability.Unit -> JsonPrimitive(capability.name)
    is ConsequenceCapability.OutletCall -> buildJsonObject { put("OutletCall", capability.outletId) }
    is ConsequenceCapability.Custom -> buildJsonObject { put("Custom", capability.name) }
}
