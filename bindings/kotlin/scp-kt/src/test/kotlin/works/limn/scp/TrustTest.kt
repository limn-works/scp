// TrustTest.kt — Unit tests for the Kotlin trust-signal SDK wrappers
// (ADR-059, spec §7.2.4 / §7.3.2).
//
// These exercise the PURE projection/serialization logic that sits on top of
// the UniFFI bridge — mapping the typed CapabilityValidationRecord /
// ParticipationRecordView onto the idiomatic CapabilityValidation /
// BehavioralRecord, the allValid collapse, the empty-log zeroed record, and the
// cached-attestation wire serialization. None of these require the linked Rust
// cdylib (the records are plain data classes), so they run regardless of native
// library availability. The full SCP.evaluateTrust / SCP.ucanEvaluate /
// SCP.participationRecord round-trips dispatch through `inner` and are covered
// by the real-FFI suite (which skips when the native lib is absent).

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import uniffi.scp.CapabilityValidationRecord
import uniffi.scp.ParticipationRecordView
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TrustTest {
    @Test
    fun `ucanEvaluate projection maps the six per-stage booleans`() {
        val record =
            CapabilityValidationRecord(
                tokensValid = true,
                signaturesValid = false,
                withinCeiling = true,
                nonceValid = false,
                notRevoked = true,
                timeBoundsValid = false,
            )
        val validation = CapabilityValidation.fromRecord(record)
        assertTrue(validation.tokensValid)
        assertFalse(validation.signaturesValid)
        assertTrue(validation.withinCeiling)
        assertFalse(validation.nonceValid)
        assertTrue(validation.notRevoked)
        assertFalse(validation.timeBoundsValid)
    }

    @Test
    fun `allValid is the conjunction of all six stages`() {
        val allTrue =
            CapabilityValidation(
                tokensValid = true,
                signaturesValid = true,
                withinCeiling = true,
                nonceValid = true,
                notRevoked = true,
                timeBoundsValid = true,
            )
        assertTrue(allTrue.allValid)

        val oneFalse = allTrue.copy(nonceValid = false)
        assertFalse(oneFalse.allValid)
    }

    @Test
    fun `participationRecord projection maps all twelve facts`() {
        val view =
            ParticipationRecordView(
                subjectDid = "did:key:zSubject",
                participationDurationSecs = 3600uL,
                governanceActionsAgainst = 1uL,
                governanceActionsBy = 2uL,
                outletInvocationCount = 5uL,
                outletInvocationCountAnchored = false,
                contextCreationCount = 1uL,
                roleProgressionCount = 3uL,
                attestationCount = 4uL,
                attestationCountAnchored = false,
                computedAt = 1_700_000_000uL,
                eventLogRoot = "abc123",
            )
        val record = BehavioralRecord.fromView(view)
        assertEquals("did:key:zSubject", record.subjectDid)
        assertEquals(3600uL, record.participationDurationSecs)
        assertEquals(1uL, record.governanceActionsAgainst)
        assertEquals(2uL, record.governanceActionsBy)
        assertEquals(5uL, record.outletInvocationCount)
        assertFalse(record.outletInvocationCountAnchored)
        assertEquals(1uL, record.contextCreationCount)
        assertEquals(3uL, record.roleProgressionCount)
        assertEquals(4uL, record.attestationCount)
        assertFalse(record.attestationCountAnchored)
        assertEquals(1_700_000_000uL, record.computedAt)
        assertEquals("abc123", record.eventLogRoot)
    }

    @Test
    fun `zeroed behavioral record is fully zeroed but carries the subject DID`() {
        val record = BehavioralRecord.zeroed("did:key:zSubject")
        assertEquals("did:key:zSubject", record.subjectDid)
        assertEquals(0uL, record.participationDurationSecs)
        assertEquals(0uL, record.governanceActionsAgainst)
        assertEquals(0uL, record.governanceActionsBy)
        assertEquals(0uL, record.outletInvocationCount)
        assertFalse(record.outletInvocationCountAnchored)
        assertEquals(0uL, record.contextCreationCount)
        assertEquals(0uL, record.roleProgressionCount)
        assertEquals(0uL, record.attestationCount)
        assertFalse(record.attestationCountAnchored)
        assertEquals(0uL, record.computedAt)
        assertEquals("", record.eventLogRoot)
    }

    @Test
    fun `no participation facts code matches the bridge structured code`() {
        assertEquals("SCP-CTX-2076", NO_PARTICIPATION_FACTS_CODE)
    }

    @Test
    fun `trust evaluation carries the resolved context label and both layers`() {
        val evaluation =
            TrustEvaluation(
                subjectDid = "did:key:zSubject",
                contextId = "ctx-resolved",
                capabilityValidation =
                    CapabilityValidation(
                        tokensValid = true,
                        signaturesValid = true,
                        withinCeiling = true,
                        nonceValid = true,
                        notRevoked = true,
                        timeBoundsValid = true,
                    ),
                behavioralRecord = BehavioralRecord.zeroed("did:key:zSubject"),
            )
        assertEquals("did:key:zSubject", evaluation.subjectDid)
        assertEquals("ctx-resolved", evaluation.contextId)
        assertTrue(evaluation.capabilityValidation.allValid)
        assertEquals("did:key:zSubject", evaluation.behavioralRecord.subjectDid)
        assertTrue(evaluation.attestations.isEmpty())
    }

    @Test
    fun `cached attestation serializes to serde-canonical snake_case wire`() {
        val envelope =
            CachedAttestationEnvelope(
                id = "att-1",
                attestationType = "IdentityLink",
                issuer = "did:key:zIssuer",
                subject = "did:key:zSubject",
                claim = Json.parseToJsonElement("""{"device":"iphone","verified":true}"""),
                issuedAt = 1_700_000_000uL,
                revocationStatus = Json.parseToJsonElement(""""NotRevoked""""),
                signature = List(64) { 0u.toUByte() },
                evidence =
                    CachedAttestationEvidence(
                        evidenceType = "manual",
                        data = Json.parseToJsonElement(""""ok""""),
                    ),
                expiresAt = 1_800_000_000uL,
            )
        val cached = CachedAttestation(attestation = envelope, verifiedAt = 1_700_000_100uL, ttlSecs = 3600uL)

        val json = encodeCachedAttestationsJson(listOf(cached))
        val array = Json.parseToJsonElement(json).jsonArray
        assertEquals(1, array.size)
        val first = array[0].jsonObject
        assertEquals(1_700_000_100L, first["verified_at"]!!.jsonPrimitive.content.toLong())
        assertEquals(3600L, first["ttl_secs"]!!.jsonPrimitive.content.toLong())

        val att = first["attestation"]!!.jsonObject
        assertEquals("att-1", att["id"]!!.jsonPrimitive.content)
        assertEquals("IdentityLink", att["attestation_type"]!!.jsonPrimitive.content)
        assertEquals(1_700_000_000L, att["issued_at"]!!.jsonPrimitive.content.toLong())
        assertEquals(1_800_000_000L, att["expires_at"]!!.jsonPrimitive.content.toLong())
        assertEquals(64, att["signature"]!!.jsonArray.size)
        val evidence = att["evidence"]!!.jsonObject
        assertEquals("manual", evidence["evidence_type"]!!.jsonPrimitive.content)
    }

    @Test
    fun `empty cached attestation list serializes to empty array`() {
        assertEquals("[]", encodeCachedAttestationsJson(emptyList()))
    }
}
