// Trust.kt — Kotlin SDK trust-signal types and wire serialization.
//
// The UniFFI bridge (`crates/scp-ffi/uniffi/src/bridge.rs`) exports the raw
// trust-signal ops these types wrap idiomatically:
//   - `ucanEvaluate(...)` returns the typed `CapabilityValidationRecord`
//     (six per-stage booleans).
//   - `participationRecord(...)` returns the typed `ParticipationRecordView`
//     (the twelve §7.3.2 facts).
// The idiomatic [CapabilityValidation] / [BehavioralRecord] / [TrustEvaluation]
// types and the [SCP.ucanEvaluate] / [SCP.participationRecord] /
// [SCP.evaluateTrust] wrappers (in Scp.kt) sit ON TOP of those, mirroring the
// Python (`scp_sdk.trust`) and TypeScript (`scp.ts` / `types.ts`) SDKs
// field-for-field.
//
// Provenance: ADR-057 (.docs/adrs/phase-2.md), spec §7.2.4 / §7.3.2
// (.docs/specs/07-trust-validation-and-capabilities.md), ADR-017
// (.docs/adrs/phase-4.md).

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
import uniffi.scp.CapabilityValidationRecord
import uniffi.scp.ParticipationRecordView

/**
 * Stable error code (spec §7.3.2) the core surfaces when a context has no
 * recorded participation facts yet (an empty event log).
 *
 * [SCP.evaluateTrust] branches Layer 2 on this STRUCTURED code — never on error
 * prose — folding "no facts yet" into a zeroed behavioral record while letting
 * every other failure propagate. Mirrors the Python/TypeScript SDKs'
 * `NO_PARTICIPATION_FACTS_CODE`.
 */
const val NO_PARTICIPATION_FACTS_CODE: String = "SCP-CTX-2076"

/**
 * Layer 1: protocol-enforcement results (mechanical, pass/fail).
 *
 * The six per-stage booleans are the canonical structured result of the
 * read-only [SCP.ucanEvaluate] diagnostic (spec §7.2.4, ADR-057): one boolean
 * per pipeline-stage group of the 11-step ADR-016 pipeline. They are populated
 * directly from the bridge's typed [CapabilityValidationRecord] — never
 * reverse-engineered by parsing error prose. The result is strictly ordered and
 * short-circuiting: a field is `true` only if its stage ran *and* passed, so the
 * first failing stage and every later stage are `false`.
 *
 * Mirrors the Python SDK `CapabilityValidation` dataclass and the TypeScript SDK
 * `CapabilityValidation` interface field-for-field.
 *
 * @property tokensValid Step 1: the UCAN token parsed and its structure validated.
 * @property signaturesValid Steps 2-7: signatures, the full delegation chain,
 *   root issuer, audience, key scope, Category-A enforcement, and attenuation
 *   verify. The invoked-capability grant-match (step 6) is included ONLY when a
 *   challenge capability is supplied; in intrinsic-validity mode (the mode
 *   [SCP.evaluateTrust] uses — no challenge) step 6 is SKIPPED and this field
 *   reflects only the structural checks.
 * @property withinCeiling Step 8: every requested capability is within the
 *   context's ceiling.
 * @property nonceValid Step 9: nonce format, freshness, and uniqueness passed.
 *   Probed read-only — the nonce is NOT recorded.
 * @property notRevoked Step 10: no token's revocation CID is on the revocation list.
 * @property timeBoundsValid Step 11: `exp`/`nbf` time bounds are valid.
 */
data class CapabilityValidation(
    val tokensValid: Boolean,
    val signaturesValid: Boolean,
    val withinCeiling: Boolean,
    val nonceValid: Boolean,
    val notRevoked: Boolean,
    val timeBoundsValid: Boolean,
) {
    /**
     * `true` iff every per-stage check passed.
     *
     * The one obvious correct happy-path call: collapses the six per-stage
     * booleans with a logical AND so consumers do not hand-roll the conjunction
     * (and cannot silently omit a field when a new stage is added). A token is
     * protocol-compliant only when all six are `true`. Mirrors the Python
     * `CapabilityValidation.all_valid` accessor and the TypeScript `allValid`
     * helper.
     *
     * SECURITY: this is a DIAGNOSTIC, NEVER an authorization decision. It reports
     * that the UCAN tokens are *intrinsically well-formed and valid*; it does NOT
     * authorize any action. In intrinsic mode (no challenge capability supplied —
     * the mode [SCP.evaluateTrust] uses), the invoked-capability grant-match
     * (step 6) is SKIPPED, so [allValid] being `true` does NOT assert that any
     * specific capability is granted. To gate an action, pass the concrete
     * capability to [SCP.ucanEvaluate] (which then includes grant-match in
     * [signaturesValid]) — or use the enforcing UCAN validation path. Treating
     * [allValid] as "the agent may do X" is a security error.
     */
    val allValid: Boolean
        get() =
            tokensValid &&
                signaturesValid &&
                withinCeiling &&
                nonceValid &&
                notRevoked &&
                timeBoundsValid

    companion object {
        /**
         * Projects the typed UniFFI [CapabilityValidationRecord] onto this SDK
         * type. Reads the six booleans directly — the per-check breakdown comes
         * from the structured record, never from parsing error prose (spec
         * §7.2.4, ADR-057 Decision 3).
         */
        fun fromRecord(record: CapabilityValidationRecord): CapabilityValidation =
            CapabilityValidation(
                tokensValid = record.tokensValid,
                signaturesValid = record.signaturesValid,
                withinCeiling = record.withinCeiling,
                nonceValid = record.nonceValid,
                notRevoked = record.notRevoked,
                timeBoundsValid = record.timeBoundsValid,
            )
    }
}

/**
 * Layer 2: the participation facts (§7.3.2) for a subject in a context.
 *
 * The scalar projection of scp-core's `ParticipationRecord`, computed ONCE in
 * the shared Rust core and surfaced through the UniFFI `participation_record` op
 * ([ParticipationRecordView]). The SDK RECEIVES these facts rather than
 * re-aggregating event-log collections client-side — eliminating cross-binding
 * divergence by construction. Mirrors the Python SDK `BehavioralRecord`, the
 * TypeScript SDK `BehavioralRecord`, and the Rust `ParticipationFacts` 1:1.
 *
 * The six leaf-derived facts (participation duration, governance actions
 * against/by, context creation, role progression, tool invocation count) come
 * from the context's convergent Merkle event log. [attestationCount] is the one
 * exception: it is a credential-layer fact (§7.4), NOT event-log-derived, NOT
 * covered by [eventLogRoot], and **verifier-relative** (two agents may compute
 * different counts from different accessible attestation sets).
 *
 * @property subjectDid The DID whose participation is summarized.
 * @property participationDurationSecs Total seconds of context participation.
 * @property governanceActionsAgainst Governance actions against this identity
 *   (the subject is the projected target).
 * @property governanceActionsBy Governance actions initiated by this identity.
 * @property toolInvocationCount Total tool invocations across all tool types.
 * @property toolInvocationCountAnchored Whether [toolInvocationCount] is anchored
 *   in the canonical Merkle log. `false` until ADR-051 makes `ToolInvoked` a
 *   convergent leaf — consumers MUST NOT treat the count as Merkle-proven while
 *   this is `false`.
 * @property contextCreationCount Contexts created by the subject (`ChildContextCreated`).
 * @property roleProgressionCount Role transitions for the subject (`RoleAssigned`).
 * @property attestationCount Accessible, currently-valid credential-layer
 *   attestations (§7.4) for the subject. Verifier-relative; NOT a context-event count.
 * @property attestationCountAnchored Whether [attestationCount] is anchored in /
 *   verifiable against a context Merkle root. Always `false`: a credential-layer,
 *   verifier-relative fact (§7.4), never a context-event-log count (§7.3.2).
 * @property computedAt Unix timestamp (seconds) when the record was computed.
 * @property eventLogRoot Merkle root (hex) of the event log at computation time.
 */
data class BehavioralRecord(
    val subjectDid: String,
    val participationDurationSecs: ULong,
    val governanceActionsAgainst: ULong,
    val governanceActionsBy: ULong,
    val toolInvocationCount: ULong,
    val toolInvocationCountAnchored: Boolean,
    val contextCreationCount: ULong,
    val roleProgressionCount: ULong,
    val attestationCount: ULong,
    val attestationCountAnchored: Boolean,
    val computedAt: ULong,
    val eventLogRoot: String,
) {
    companion object {
        /** Projects the typed UniFFI [ParticipationRecordView] onto this SDK type. */
        fun fromView(view: ParticipationRecordView): BehavioralRecord =
            BehavioralRecord(
                subjectDid = view.subjectDid,
                participationDurationSecs = view.participationDurationSecs,
                governanceActionsAgainst = view.governanceActionsAgainst,
                governanceActionsBy = view.governanceActionsBy,
                toolInvocationCount = view.toolInvocationCount,
                toolInvocationCountAnchored = view.toolInvocationCountAnchored,
                contextCreationCount = view.contextCreationCount,
                roleProgressionCount = view.roleProgressionCount,
                attestationCount = view.attestationCount,
                attestationCountAnchored = view.attestationCountAnchored,
                computedAt = view.computedAt,
                eventLogRoot = view.eventLogRoot,
            )

        /**
         * A zeroed record for a subject in a context with no recorded
         * participation facts yet (an empty event log → `SCP-CTX-2076`). All
         * counts are `0`, both `*Anchored` flags `false`, [eventLogRoot] empty —
         * identical in shape to the Python/TypeScript SDKs' empty-log record.
         */
        fun zeroed(subjectDid: String): BehavioralRecord =
            BehavioralRecord(
                subjectDid = subjectDid,
                participationDurationSecs = 0uL,
                governanceActionsAgainst = 0uL,
                governanceActionsBy = 0uL,
                toolInvocationCount = 0uL,
                toolInvocationCountAnchored = false,
                contextCreationCount = 0uL,
                roleProgressionCount = 0uL,
                attestationCount = 0uL,
                attestationCountAnchored = false,
                computedAt = 0uL,
                eventLogRoot = "",
            )
    }
}

/**
 * Layer 3: a summary of an attestation for the subject.
 *
 * Mirrors the TypeScript SDK `AttestationSummary` interface. Trust evaluation
 * reports the attestation layer as an empty list until the Layer-3 source is
 * wired; the type exists so the [TrustEvaluation] shape is identical across
 * bindings (Agent-first API design tenet).
 *
 * @property type Attestation type identifier.
 * @property issuer DID of the attestation issuer.
 * @property valid Whether the attestation is currently valid.
 * @property revoked Whether the attestation has been revoked.
 */
data class AttestationSummary(
    val type: String,
    val issuer: String,
    val valid: Boolean,
    val revoked: Boolean,
)

/**
 * The complete structured trust evaluation for a subject in a context
 * (spec §7.2.4, ADR-057). The protocol provides the data, not the verdict — the
 * caller decides what to do with it.
 *
 * Mirrors the TypeScript SDK `TrustEvaluation` interface and the Python SDK
 * `TrustEvaluation` dataclass: Layer 1 ([capabilityValidation]) is the per-stage
 * boolean result AND-combined across the evaluated token set; Layer 2
 * ([behavioralRecord]) is the Rust-computed participation record; Layer 3
 * ([attestations]) is the attestation summary set.
 *
 * @property subjectDid DID of the evaluated subject.
 * @property contextId ID of the context the evaluation applies to (the resolved
 *   canonical id the layers were computed against).
 * @property capabilityValidation Layer 1 protocol enforcement, AND-combined
 *   across the evaluated capability-token set. With no tokens supplied every
 *   field is `false` (no stage was observed to pass).
 * @property behavioralRecord Layer 2 behavioral validation. Always a record,
 *   never null — an empty event log yields a zeroed [BehavioralRecord].
 * @property attestations Layer 3 attestation summaries for the subject.
 */
data class TrustEvaluation(
    val subjectDid: String,
    val contextId: String,
    val capabilityValidation: CapabilityValidation,
    val behavioralRecord: BehavioralRecord,
    val attestations: List<AttestationSummary> = emptyList(),
)

// ---------------------------------------------------------------------------
// Cached-attestation wire DTOs (ADR-017 §7.4.1)
// ---------------------------------------------------------------------------

/**
 * Optional evidence supporting a [CachedAttestationEnvelope].
 *
 * @property evidenceType The evidence type discriminator.
 * @property data Type-specific evidence data (arbitrary JSON).
 */
data class CachedAttestationEvidence(
    val evidenceType: String,
    val data: JsonElement,
)

/**
 * A `std::time::Duration` as the Rust core's serde representation
 * (`{ secs, nanos }`), used for a renewable attestation's renewal interval.
 *
 * @property secs Whole seconds.
 * @property nanos Sub-second nanoseconds.
 */
data class CachedAttestationDuration(
    val secs: ULong,
    val nanos: UInt,
)

/**
 * Wire-format attestation envelope (ADR-017 §7.4.1).
 *
 * A pass-through DTO whose JSON keys are the serde-canonical snake_case the Rust
 * core deserializes, NOT the camelCase the SDK uses for core-modeled types.
 * Mirrors the Python SDK `CachedAttestationEnvelope` TypedDict and the
 * TypeScript SDK `CachedAttestationEnvelope` interface 1:1. Freeform fields
 * ([claim], [evidence].data, [revocationStatus]) are [JsonElement] — the Kotlin
 * idiom for the arbitrary JSON the Rust core deserializes as `serde_json::Value`.
 *
 * @property id Unique attestation identifier.
 * @property attestationType Attestation type (serde tag, e.g. `"IdentityLink"`).
 * @property issuer DID of the attestation issuer.
 * @property subject DID of the attestation subject.
 * @property claim Type-specific claim data (arbitrary JSON).
 * @property issuedAt Unix timestamp (seconds) when the attestation was issued.
 * @property revocationStatus Current revocation status (serde-tagged JSON).
 * @property signature Ed25519 signature over the attestation content (64 bytes).
 * @property evidence Optional evidence supporting the attestation.
 * @property expiresAt Optional expiry timestamp (seconds).
 * @property renewalInterval Optional renewal interval.
 * @property renewedAt Timestamp (seconds) of the last renewal, if renewable.
 */
data class CachedAttestationEnvelope(
    val id: String,
    val attestationType: String,
    val issuer: String,
    val subject: String,
    val claim: JsonElement,
    val issuedAt: ULong,
    val revocationStatus: JsonElement,
    val signature: List<UByte>,
    val evidence: CachedAttestationEvidence? = null,
    val expiresAt: ULong? = null,
    val renewalInterval: CachedAttestationDuration? = null,
    val renewedAt: ULong? = null,
)

/**
 * A verified attestation with cache TTL metadata (ADR-017).
 *
 * Pass a list of these to [SCP.participationRecord] (or [SCP.evaluateTrust]) to
 * seed the bridge's trust store before it sources the subject's verified set.
 * Mirrors the Rust `CachedAttestation`, the Python SDK `CachedAttestation`
 * TypedDict, and the TypeScript SDK `CachedAttestation` interface 1:1.
 *
 * @property attestation The verified attestation envelope.
 * @property verifiedAt Unix timestamp (seconds) when the attestation was last verified.
 * @property ttlSecs Time-to-live in seconds for the cache entry.
 */
data class CachedAttestation(
    val attestation: CachedAttestationEnvelope,
    val verifiedAt: ULong,
    val ttlSecs: ULong,
)

/**
 * Serializes a cached-attestation list to the serde-canonical JSON the bridge
 * `participation_record` op deserializes. Shared by [SCP.participationRecord]
 * and [SCP.evaluateTrust] so the projection lives in one place. An empty list
 * encodes to `"[]"` — the bridge then reports only what its trust store already
 * holds (verifier-relative, §7.4). Built with [buildJsonArray] (matching
 * `encodeConsequenceRulesJson` in ConsequenceRule.kt) so the encoder cannot
 * inject malformed JSON.
 */
fun encodeCachedAttestationsJson(cachedAttestations: List<CachedAttestation>): String =
    Json.encodeToString(
        JsonArray.serializer(),
        buildJsonArray { cachedAttestations.forEach { add(encodeCachedAttestationElement(it)) } },
    )

private fun encodeCachedAttestationElement(cached: CachedAttestation): JsonObject =
    buildJsonObject {
        put("attestation", encodeEnvelopeElement(cached.attestation))
        put("verified_at", cached.verifiedAt.toLong())
        put("ttl_secs", cached.ttlSecs.toLong())
    }

private fun encodeEnvelopeElement(envelope: CachedAttestationEnvelope): JsonObject =
    buildJsonObject {
        put("id", envelope.id)
        put("attestation_type", envelope.attestationType)
        put("issuer", envelope.issuer)
        put("subject", envelope.subject)
        put("claim", envelope.claim)
        put("issued_at", envelope.issuedAt.toLong())
        put("revocation_status", envelope.revocationStatus)
        put(
            "signature",
            buildJsonArray { envelope.signature.forEach { add(it.toInt()) } },
        )
        put("evidence", encodeEvidenceElement(envelope.evidence))
        put("expires_at", envelope.expiresAt?.let { JsonPrimitive(it.toLong()) } ?: JsonNull)
        put("renewal_interval", encodeDurationElement(envelope.renewalInterval))
        put("renewed_at", envelope.renewedAt?.let { JsonPrimitive(it.toLong()) } ?: JsonNull)
    }

private fun encodeEvidenceElement(evidence: CachedAttestationEvidence?): JsonElement =
    if (evidence == null) {
        JsonNull
    } else {
        buildJsonObject {
            put("evidence_type", evidence.evidenceType)
            put("data", evidence.data)
        }
    }

private fun encodeDurationElement(duration: CachedAttestationDuration?): JsonElement =
    if (duration == null) {
        JsonNull
    } else {
        buildJsonObject {
            put("secs", duration.secs.toLong())
            put("nanos", duration.nanos.toLong())
        }
    }
