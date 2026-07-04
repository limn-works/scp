// TrustAggregateTest.kt — Encoder wire-shape tests for the typed
// trust-aggregation input shapes (ADR-058, spec §7.3).
//
// These pin the TrustAggregate.kt encoders against the exact
// `serde_json::to_string` shapes the Rust bridge deserializes: snake_case
// struct fields, bare AttestationType map keys, byte arrays as JSON number
// arrays, explicit `null` for an absent attestor attestation, and the Rust
// serde defaults for the ThresholdRequirement penalty fields. The fixtures
// mirror the TypeScript SDK `trust.test.ts` and Swift SDK
// `TrustAggregateTests.swift` encoder tests 1:1. Pure serialization logic —
// no native library required.

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class TrustAggregateTest {
    /** A structurally-valid signed event with real 32/64 byte arrays. */
    private fun makeEvent(
        prevHash: List<UByte> = List(32) { 0.toUByte() },
        signature: List<UByte> = List(64) { 5.toUByte() },
        payloadData: List<UByte> = emptyList(),
    ): EventLogEntry =
        EventLogEntry(
            eventType = "MessageSent",
            actorDid = "did:dht:actor",
            timestamp = 1_700_000_000uL,
            sequence = 0uL,
            payload = EventLogEntryPayload(data = payloadData),
            prevHash = prevHash,
            signature = signature,
        )

    /** Asserts two JSON strings are structurally equal (order-independent). */
    private fun assertJsonEquals(
        expected: String,
        actual: String,
    ) {
        assertEquals(Json.parseToJsonElement(expected), Json.parseToJsonElement(actual))
    }

    @Test
    fun `event log entry encodes the full 7-field snake_case signed event`() {
        assertJsonEquals(
            """
            [{"event_type":"MessageSent",
              "actor_did":"did:dht:actor",
              "timestamp":1700000000,
              "sequence":0,
              "payload":{"data":[1,2,3]},
              "prev_hash":[${(0 until 32).joinToString(",")}],
              "signature":[${List(64) { 5 }.joinToString(",")}]}]
            """.trimIndent(),
            encodeEventLogEntriesJson(
                listOf(
                    makeEvent(
                        prevHash = List(32) { it.toUByte() },
                        payloadData = listOf(1u, 2u, 3u),
                    ),
                ),
            ),
        )
    }

    @Test
    fun `wrong-length event byte arrays throw before any bridge call`() {
        val wrongPrevHash =
            assertFailsWith<IllegalArgumentException> {
                encodeEventLogEntriesJson(
                    listOf(makeEvent(prevHash = listOf(1u, 2u, 3u))),
                )
            }
        assertTrue(
            wrongPrevHash.message!!.contains(
                "EventLogEntry.prevHash must be exactly 32 elements, got 3",
            ),
        )

        val wrongSignature =
            assertFailsWith<IllegalArgumentException> {
                encodeEventLogEntriesJson(
                    listOf(makeEvent(signature = List(63) { 5.toUByte() })),
                )
            }
        assertTrue(
            wrongSignature.message!!.contains(
                "EventLogEntry.signature must be exactly 64 elements, got 63",
            ),
        )
    }

    @Test
    fun `merkle root encodes as a 32-element number array`() {
        assertJsonEquals(
            "[${(0 until 32).joinToString(",")}]",
            encodeMerkleRootJson(List(32) { it.toUByte() }),
        )
    }

    @Test
    fun `wrong-length merkle root throws before any bridge call`() {
        val error =
            assertFailsWith<IllegalArgumentException> {
                encodeMerkleRootJson(listOf(1u, 2u, 3u))
            }
        assertTrue(
            error.message!!.contains(
                "AggregatedTrustInput.merkleRoot must be exactly 32 elements, got 3",
            ),
        )
    }

    @Test
    fun `threshold requirements encode with bare type keys and serde defaults`() {
        assertJsonEquals(
            """
            {"Endorsement":{
              "required_count":2,
              "total_attestors":3,
              "independence_threshold":0.5,
              "shared_context_penalty":0.1,
              "shared_context_penalty_cap":0.5,
              "mutual_endorsement_penalty":0.2}}
            """.trimIndent(),
            encodeThresholdRequirementsJson(
                mapOf(
                    AttestationType.ENDORSEMENT to
                        ThresholdRequirement(
                            requiredCount = 2u,
                            totalAttestors = 3u,
                            independenceThreshold = 0.5,
                        ),
                ),
            ),
        )
    }

    @Test
    fun `all eight attestation types carry the bare PascalCase wire name`() {
        assertEquals(
            setOf(
                "IdentityLink", "CapabilityDelegation", "ToolIntegrity", "AgentCapability",
                "Endorsement", "RoleAssignment", "ContextEndorsement", "ParticipationWitness",
            ),
            AttestationType.entries.map { it.wireName }.toSet(),
        )
    }

    @Test
    fun `attestor info encodes an explicit-null absent attestation`() {
        assertJsonEquals(
            """
            {"Endorsement":[{
              "did":"did:dht:attestor",
              "context_memberships":["ctx-1","ctx-2"],
              "endorsements":["did:dht:other"],
              "attestation":null}]}
            """.trimIndent(),
            encodeAttestorSetsJson(
                mapOf(
                    AttestationType.ENDORSEMENT to
                        listOf(
                            AttestorInfo(
                                did = "did:dht:attestor",
                                contextMemberships = listOf("ctx-1", "ctx-2"),
                                endorsements = listOf("did:dht:other"),
                            ),
                        ),
                ),
            ),
        )
    }

    @Test
    fun `attestor info encodes a nested envelope in the serde snake_case shape`() {
        assertJsonEquals(
            """
            {"Endorsement":[{
              "did":"did:dht:attestor",
              "context_memberships":[],
              "endorsements":[],
              "attestation":{
                "id":"att-1",
                "attestation_type":"Endorsement",
                "issuer":"did:dht:attestor",
                "subject":"did:dht:subject",
                "claim":{"endorsed":true},
                "issued_at":1000,
                "revocation_status":"Active",
                "signature":[1,2,3],
                "evidence":null,
                "expires_at":null,
                "renewal_interval":null,
                "renewed_at":null}}]}
            """.trimIndent(),
            encodeAttestorSetsJson(
                mapOf(
                    AttestationType.ENDORSEMENT to
                        listOf(
                            AttestorInfo(
                                did = "did:dht:attestor",
                                contextMemberships = emptyList(),
                                endorsements = emptyList(),
                                attestation =
                                    CachedAttestationEnvelope(
                                        id = "att-1",
                                        attestationType = "Endorsement",
                                        issuer = "did:dht:attestor",
                                        subject = "did:dht:subject",
                                        claim = buildJsonObject { put("endorsed", true) },
                                        issuedAt = 1000uL,
                                        revocationStatus =
                                            Json.parseToJsonElement("\"Active\""),
                                        signature = listOf(1u, 2u, 3u),
                                    ),
                            ),
                        ),
                ),
            ),
        )
    }
}
