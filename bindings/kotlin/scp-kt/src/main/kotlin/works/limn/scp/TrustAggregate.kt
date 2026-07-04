// TrustAggregate.kt — Typed Kotlin SDK shapes for the trust-aggregation and
// challenge trust-input surfaces (ADR-058, Ops C/D of the typed trust-input
// convention).
//
// Mirrors `scp_event_log::Event` and `scp_protocol::trust::{attestation,
// aggregate, challenge}`: EventLogEntry (§7.3 aggregation events),
// AttestationType / ThresholdRequirement / AttestorInfo (§7.3.5 threshold
// verification). The SDK exposes typed shapes (no stringly-typed JSON) and
// serializes to the Rust serde wire format at the bridge boundary —
// [SCP.aggregateTrustInput] in Scp.kt calls the encoders below before
// crossing FFI. Models are plain data classes with `buildJsonObject` encoders
// (the Trust.kt cached-attestation family convention) because they interlock
// with [CachedAttestationEnvelope]; freeform fields are [JsonElement].
// Mirrors the Swift SDK `Trust.swift` aggregation types and the TypeScript
// SDK `types.ts` aggregation types field-for-field.
//
// Provenance: ADR-058 (.docs/adrs/ADR-058-typed-sdk-trust-input-surface.md),
// spec §7.3 (.docs/specs/07-trust-validation-and-capabilities.md), ADR-017 /
// ADR-011 (.docs/adrs/phase-4.md, phase-2.md).

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Attestation type (ADR-017).
 *
 * Mirrors the Rust `AttestationType` enum (`scp-core`) — the 8 unit variants
 * serialize as bare PascalCase strings ([wireName]), both as values and as
 * the `thresholdRequirements` / `attestorSets` map keys. Mirrors the Swift
 * SDK `AttestationType` enum and the TypeScript SDK `AttestationType` union
 * 1:1.
 *
 * @property wireName The serde-canonical variant string on the wire.
 */
enum class AttestationType(val wireName: String) {
    /** Links an identity to an external identifier. */
    IDENTITY_LINK("IdentityLink"),

    /** Delegates a capability to another DID. */
    CAPABILITY_DELEGATION("CapabilityDelegation"),

    /** Attests to the integrity of a tool. */
    TOOL_INTEGRITY("ToolIntegrity"),

    /** Attests to an agent's capability. */
    AGENT_CAPABILITY("AgentCapability"),

    /** A general endorsement. */
    ENDORSEMENT("Endorsement"),

    /** Assigns a role to a DID. */
    ROLE_ASSIGNMENT("RoleAssignment"),

    /** Endorses a context. */
    CONTEXT_ENDORSEMENT("ContextEndorsement"),

    /** Witnesses participation facts. */
    PARTICIPATION_WITNESS("ParticipationWitness"),
}

/**
 * Type-specific data carried by an [EventLogEntry].
 *
 * Mirrors the Rust `EventPayload` (`scp-event-log`): opaque payload bytes as
 * a JSON number array. An empty [data] list is the canonical representation
 * for non-parameterized events.
 *
 * @property data Opaque payload bytes. Interpretation depends on the event type.
 */
data class EventLogEntryPayload(
    val data: List<UByte>,
)

/**
 * A full signed protocol event in a context event log (ADR-011).
 *
 * The serde wire shape of the Rust `Event` (`scp-event-log`) the bridge
 * deserializes for [SCP.aggregateTrustInput] (`Vec<Event>`) — the INPUT wire
 * form, distinct from the projected event the event-log query surface returns
 * (which omits the hash-chain and signature fields). Mirrors the Swift SDK
 * `EventLogEntry` and the TypeScript/Python models 1:1.
 *
 * @property eventType Event type — a Rust `EventType` variant name (e.g.
 *   `"MessageSent"`).
 * @property actorDid DID of the actor who produced this event.
 * @property timestamp Unix timestamp (seconds) when the event was created.
 * @property sequence Monotonic event sequence number within the log
 *   (0-indexed).
 * @property payload Type-specific event data.
 * @property prevHash SHA-256 hash of the previous event (hash chain), exactly
 *   32 bytes. All zeros for the first event (genesis sentinel).
 * @property signature Ed25519 signature over the serialized event content
 *   (64 bytes).
 */
data class EventLogEntry(
    val eventType: String,
    val actorDid: String,
    val timestamp: ULong,
    val sequence: ULong,
    val payload: EventLogEntryPayload,
    val prevHash: List<UByte>,
    val signature: List<UByte>,
)

/** Rust serde default for `ThresholdRequirement.shared_context_penalty`. */
private const val DEFAULT_SHARED_CONTEXT_PENALTY = 0.1

/** Rust serde default for `ThresholdRequirement.shared_context_penalty_cap`. */
private const val DEFAULT_SHARED_CONTEXT_PENALTY_CAP = 0.5

/** Rust serde default for `ThresholdRequirement.mutual_endorsement_penalty`. */
private const val DEFAULT_MUTUAL_ENDORSEMENT_PENALTY = 0.2

/**
 * N-of-M threshold requirement for attestation verification (ADR-017 §7.3.5).
 *
 * Mirrors the Rust `ThresholdRequirement` struct (`scp-core`). The three
 * penalty properties default to the Rust serde defaults (0.1 / 0.5 / 0.2) and
 * are always emitted explicitly, so the wire form is identical across
 * bindings. Mirrors the Swift SDK `ThresholdRequirement` and the
 * TypeScript/Python models 1:1.
 *
 * @property requiredCount The minimum number of valid attestations required (N).
 * @property totalAttestors The total number of attestors in the set (M). Must
 *   be >= [requiredCount].
 * @property independenceThreshold Minimum independence score, in [0.0, 1.0].
 * @property sharedContextPenalty Independence penalty per shared context
 *   membership. Default: 0.1.
 * @property sharedContextPenaltyCap Maximum total shared-context penalty for
 *   a single pair. Default: 0.5.
 * @property mutualEndorsementPenalty Independence penalty per mutual
 *   endorsement direction. Default: 0.2.
 */
data class ThresholdRequirement(
    val requiredCount: UInt,
    val totalAttestors: UInt,
    val independenceThreshold: Double,
    val sharedContextPenalty: Double = DEFAULT_SHARED_CONTEXT_PENALTY,
    val sharedContextPenaltyCap: Double = DEFAULT_SHARED_CONTEXT_PENALTY_CAP,
    val mutualEndorsementPenalty: Double = DEFAULT_MUTUAL_ENDORSEMENT_PENALTY,
)

/**
 * Information about an attestor used for independence scoring (ADR-017
 * §7.3.5).
 *
 * Mirrors the Rust `AttestorInfo` struct (`scp-core`). The optional
 * [attestation] is a full attestation envelope
 * ([CachedAttestationEnvelope]); only attestations matching the required type
 * are considered. An absent attestation encodes as explicit JSON `null`
 * (matching `serde_json::to_string` of the Rust `Option<Attestation>`).
 *
 * @property did The DID of the attestor.
 * @property contextMemberships Context IDs the attestor is a member of.
 * @property endorsements DIDs this attestor has endorsed (mutual endorsements
 *   reduce independence).
 * @property attestation The attestation provided by this attestor, if any.
 */
data class AttestorInfo(
    val did: String,
    val contextMemberships: List<String>,
    val endorsements: List<String>,
    val attestation: CachedAttestationEnvelope? = null,
)

/** Expected element count of a 32-byte field (Rust `[u8; 32]`). */
private const val AGGREGATE_BYTES_32 = 32

/** Expected element count of a 64-byte field (Rust Ed25519 signature). */
private const val AGGREGATE_BYTES_64 = 64

/**
 * Throws [IllegalArgumentException] when a fixed-length byte-array field has
 * the wrong number of elements, so a malformed aggregation input fails at
 * encode time with a field-named error instead of surfacing as a Rust
 * deserialization (or silent verification) failure after the bridge call.
 * Mirrors the TrustAdmission.kt check (ADR-058 misuse resistance).
 */
private fun requireAggregateByteLength(
    typeName: String,
    fieldName: String,
    expectedLength: Int,
    actual: List<UByte>,
) {
    require(actual.size == expectedLength) {
        "$typeName.$fieldName must be exactly $expectedLength elements, got ${actual.size}"
    }
}

/**
 * Encodes a typed [EventLogEntry] list to the JSON wire shape the bridge
 * deserializes (`Vec<scp_event_log::Event>`). Byte-array fields pass through
 * as JSON number arrays.
 *
 * @throws IllegalArgumentException if [EventLogEntry.prevHash] is not exactly
 *   32 elements or [EventLogEntry.signature] is not exactly 64 elements
 *   (before any bridge call).
 */
fun encodeEventLogEntriesJson(events: List<EventLogEntry>): String {
    for (event in events) {
        requireAggregateByteLength("EventLogEntry", "prevHash", AGGREGATE_BYTES_32, event.prevHash)
        requireAggregateByteLength(
            "EventLogEntry",
            "signature",
            AGGREGATE_BYTES_64,
            event.signature,
        )
    }
    return Json.encodeToString(
        JsonArray.serializer(),
        buildJsonArray { events.forEach { add(encodeEventLogEntryElement(it)) } },
    )
}

private fun encodeEventLogEntryElement(event: EventLogEntry): JsonObject =
    buildJsonObject {
        put("event_type", event.eventType)
        put("actor_did", event.actorDid)
        put("timestamp", event.timestamp.toLong())
        put("sequence", event.sequence.toLong())
        put(
            "payload",
            buildJsonObject {
                put("data", buildJsonArray { event.payload.data.forEach { add(it.toInt()) } })
            },
        )
        put("prev_hash", buildJsonArray { event.prevHash.forEach { add(it.toInt()) } })
        put("signature", buildJsonArray { event.signature.forEach { add(it.toInt()) } })
    }

/**
 * Encodes a 32-byte Merkle root to the JSON wire shape the bridge
 * deserializes (`[u8; 32]` as a number array).
 *
 * @throws IllegalArgumentException if [merkleRoot] is not exactly 32 elements
 *   (before any bridge call).
 */
fun encodeMerkleRootJson(merkleRoot: List<UByte>): String {
    requireAggregateByteLength(
        "AggregatedTrustInput",
        "merkleRoot",
        AGGREGATE_BYTES_32,
        merkleRoot,
    )
    return Json.encodeToString(
        JsonArray.serializer(),
        buildJsonArray { merkleRoot.forEach { add(it.toInt()) } },
    )
}

/**
 * Encodes a typed per-[AttestationType] [ThresholdRequirement] map to the
 * JSON wire shape the bridge deserializes
 * (`HashMap<AttestationType, ThresholdRequirement>`). Map keys are the bare
 * variant strings; the three penalty fields are always emitted explicitly
 * (the Rust serde defaults when not overridden).
 */
fun encodeThresholdRequirementsJson(
    requirements: Map<AttestationType, ThresholdRequirement>,
): String =
    Json.encodeToString(
        JsonObject.serializer(),
        buildJsonObject {
            requirements.forEach { (attestationType, requirement) ->
                put(
                    attestationType.wireName,
                    buildJsonObject {
                        put("required_count", requirement.requiredCount.toLong())
                        put("total_attestors", requirement.totalAttestors.toLong())
                        put("independence_threshold", requirement.independenceThreshold)
                        put("shared_context_penalty", requirement.sharedContextPenalty)
                        put("shared_context_penalty_cap", requirement.sharedContextPenaltyCap)
                        put("mutual_endorsement_penalty", requirement.mutualEndorsementPenalty)
                    },
                )
            }
        },
    )

/**
 * Encodes a typed per-[AttestationType] [AttestorInfo] map to the JSON wire
 * shape the bridge deserializes
 * (`HashMap<AttestationType, Vec<AttestorInfo>>`). Map keys are the bare
 * variant strings; a nested attestation envelope (when present) is encoded
 * exactly as [encodeCachedAttestationsJson] encodes it, and an absent one
 * encodes as explicit `null`.
 */
fun encodeAttestorSetsJson(attestorSets: Map<AttestationType, List<AttestorInfo>>): String =
    Json.encodeToString(
        JsonObject.serializer(),
        buildJsonObject {
            attestorSets.forEach { (attestationType, attestors) ->
                put(
                    attestationType.wireName,
                    buildJsonArray { attestors.forEach { add(encodeAttestorInfoElement(it)) } },
                )
            }
        },
    )

private fun encodeAttestorInfoElement(attestor: AttestorInfo): JsonObject =
    buildJsonObject {
        put("did", attestor.did)
        put(
            "context_memberships",
            buildJsonArray { attestor.contextMemberships.forEach { add(it) } },
        )
        put("endorsements", buildJsonArray { attestor.endorsements.forEach { add(it) } })
        put("attestation", encodeOptionalEnvelopeElement(attestor.attestation))
    }

private fun encodeOptionalEnvelopeElement(envelope: CachedAttestationEnvelope?): JsonElement =
    if (envelope == null) {
        JsonNull
    } else {
        encodeEnvelopeElement(envelope)
    }
