// TypedContextParams.kt — The typed construction path for the UniFFI
// `ContextParams` record (ADR-058, spec 07 §7.3.4.4, ADR-017).
//
// The UniFFI record carries consequence rules, consequence config and
// capability requirements as JSON strings. This class carries them as the
// SDK's typed values and encodes them itself, as the Swift SDK's
// `ContextParams` convenience initializer in `ConsequenceRule.swift` does.

package works.limn.scp

import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.MemoryScope
import uniffi.scp.PseudonymRotationPolicy

/**
 * Context creation parameters with typed consequence rules, consequence
 * config and capability requirements; pass it to [SCP.contextCreate].
 *
 * Every other field means what the [ContextParams] field of the same name
 * means. `ceiling` is forwarded as written: an empty list makes the create
 * fail with `SCP-VALID-7005` (construction.md M2), and no default ceiling
 * replaces it.
 *
 * @property consequenceRules The context's consequence rules; `null` sets
 *   none.
 * @property consequenceConfig The context's consequence config; `null` takes
 *   the protocol default.
 * @property capabilityRequirements The admission requirements the context's
 *   governance holds (spec 07 §7.3.4.4); `null` sets none.
 * @property pseudonymRotation The context's pseudonym rotation policy;
 *   `null` sets none.
 */
data class TypedContextParams(
    val mode: ContextMode,
    val ceiling: List<String>,
    val ceilingPolicy: CeilingPolicy,
    val governance: GovernanceModel,
    val memoryScope: MemoryScope,
    val ttlSeconds: ULong,
    val promotable: Boolean,
    val minProtocolVersion: UShort = 0u,
    val maxChainDepth: UByte? = null,
    val maxNestingDepth: UInt? = null,
    val sessionCap: UInt? = null,
    val economicPolicy: String? = null,
    val consequenceRules: List<ConsequenceRule>?,
    val consequenceConfig: ConsequenceConfig?,
    val capabilityRequirements: List<CapabilityRequirement>? = null,
    val pseudonymRotation: PseudonymRotationPolicy? = null,
) {
    /** The UniFFI record, with each typed value encoded to its JSON wire form. */
    internal fun toContextParams(): ContextParams =
        ContextParams(
            mode = mode,
            ceiling = ceiling,
            ceilingPolicy = ceilingPolicy,
            governance = governance,
            memoryScope = memoryScope,
            ttlSeconds = ttlSeconds,
            promotable = promotable,
            minProtocolVersion = minProtocolVersion,
            maxChainDepth = maxChainDepth,
            maxNestingDepth = maxNestingDepth,
            sessionCap = sessionCap,
            economicPolicy = economicPolicy,
            consequenceRulesJson = consequenceRules?.let { encodeConsequenceRulesJson(it) },
            consequenceConfigJson = consequenceConfig?.let { encodeConsequenceConfigJson(it) },
            capabilityRequirementsJson = capabilityRequirements?.let { encodeCapabilityRequirementsJson(it) },
            pseudonymRotation = pseudonymRotation,
        )
}
