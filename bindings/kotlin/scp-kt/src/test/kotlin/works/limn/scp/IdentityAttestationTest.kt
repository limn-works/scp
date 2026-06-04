// IdentityAttestationTest.kt — Tests for identity link attestation wrappers (§3.5)

package works.limn.scp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Tests for the [IdentityAttestation] data class and
 * [IdentityAdvancedBindings] / [IdentityAdvancedBridge] attestation methods.
 *
 * Covers:
 * - Data class construction with defaults
 * - Data class construction with all fields
 * - Equality and inequality
 * - Bridge bindings interface compilation
 */
class IdentityAttestationTest {
    @Test
    fun `construction with defaults`() {
        val att = IdentityAttestation(
            id = "abc123",
            platform = "github.com",
            platformHandle = "alice",
            verificationMethod = "did:dht:z6Mk...#active",
            verifiedAt = 1_700_000_000L,
        )
        assertEquals("abc123", att.id)
        assertEquals("github.com", att.platform)
        assertEquals("alice", att.platformHandle)
        assertEquals("did:dht:z6Mk...#active", att.verificationMethod)
        assertEquals(1_700_000_000L, att.verifiedAt)
        assertEquals(RevocationStatus.Active, att.revocationStatus)
        assertEquals("active", att.revocationStatus.status)
        assertNull(att.platformId)
    }

    @Test
    fun `construction with all fields`() {
        val att = IdentityAttestation(
            id = "def456",
            platform = "x.com",
            platformHandle = "bob",
            verificationMethod = "did:dht:z6Mk...#agent",
            verifiedAt = 1_700_000_000L,
            revocationStatus = RevocationStatus.Revoked(
                revokedAt = 1_700_000_100L,
                reason = "compromised",
            ),
            platformId = "12345",
        )
        assertEquals("revoked", att.revocationStatus.status)
        assertEquals("12345", att.platformId)
        val revoked = att.revocationStatus as RevocationStatus.Revoked
        assertEquals(1_700_000_100L, revoked.revokedAt)
        assertEquals("compromised", revoked.reason)
    }

    @Test
    fun `RevocationStatus Active`() {
        val rs = RevocationStatus.Active
        assertEquals("active", rs.status)
    }

    @Test
    fun `RevocationStatus Revoked`() {
        val rs = RevocationStatus.Revoked(
            revokedAt = 1_700_000_100L,
            reason = "test",
        )
        assertEquals("revoked", rs.status)
        assertEquals(1_700_000_100L, rs.revokedAt)
        assertEquals("test", rs.reason)
    }

    @Test
    fun `RevocationStatus equality`() {
        assertEquals(RevocationStatus.Active, RevocationStatus.Active)
        assertEquals(
            RevocationStatus.Revoked(revokedAt = 1L, reason = "a"),
            RevocationStatus.Revoked(revokedAt = 1L, reason = "a"),
        )
        assertNotEquals(
            RevocationStatus.Active as RevocationStatus,
            RevocationStatus.Revoked(revokedAt = 1L) as RevocationStatus,
        )
    }

    @Test
    fun equality() {
        val att1 = IdentityAttestation(
            id = "abc123",
            platform = "github.com",
            platformHandle = "alice",
            verificationMethod = "did:dht:z6Mk...#active",
            verifiedAt = 1_700_000_000L,
        )
        val att2 = IdentityAttestation(
            id = "abc123",
            platform = "github.com",
            platformHandle = "alice",
            verificationMethod = "did:dht:z6Mk...#active",
            verifiedAt = 1_700_000_000L,
        )
        assertEquals(att1, att2)
    }

    @Test
    fun inequality() {
        val att1 = IdentityAttestation(
            id = "abc123",
            platform = "github.com",
            platformHandle = "alice",
            verificationMethod = "did:dht:z6Mk...#active",
            verifiedAt = 1_700_000_000L,
        )
        val att2 = IdentityAttestation(
            id = "def456",
            platform = "github.com",
            platformHandle = "alice",
            verificationMethod = "did:dht:z6Mk...#active",
            verifiedAt = 1_700_000_000L,
        )
        assertNotEquals(att1, att2)
    }

    @Test
    fun `data class copy preserves fields`() {
        val att = IdentityAttestation(
            id = "abc123",
            platform = "github.com",
            platformHandle = "alice",
            verificationMethod = "did:dht:z6Mk...#active",
            verifiedAt = 1_700_000_000L,
            platformId = "42",
        )
        val renewed = att.copy(verifiedAt = 1_800_000_000L)
        assertEquals("abc123", renewed.id)
        assertEquals(1_800_000_000L, renewed.verifiedAt)
        assertEquals("42", renewed.platformId)
    }

    @Test
    fun `fromJson parses Active revocation status string`() {
        val json = """
            {
                "id": "abc123",
                "platform": "github.com",
                "platform_handle": "alice",
                "verification_method": "did:dht:z6Mk...#active",
                "verified_at": 1700000000,
                "revocation_status": "Active"
            }
        """.trimIndent()
        val att = IdentityAttestation.fromJson(json)
        assertEquals("abc123", att.id)
        assertEquals("github.com", att.platform)
        assertEquals("alice", att.platformHandle)
        assertEquals("did:dht:z6Mk...#active", att.verificationMethod)
        assertEquals(1_700_000_000L, att.verifiedAt)
        assertTrue(att.revocationStatus is RevocationStatus.Active)
        assertNull(att.platformId)
    }

    @Test
    fun `fromJson parses Revoked revocation status object`() {
        val json = """
            {
                "id": "def456",
                "platform": "x.com",
                "platform_handle": "bob",
                "verification_method": "did:dht:z6Mk...#agent",
                "verified_at": 1700000000,
                "revocation_status": {
                    "Revoked": {
                        "revoked_at": 1700000100,
                        "reason": "compromised"
                    }
                },
                "platform_id": "12345"
            }
        """.trimIndent()
        val att = IdentityAttestation.fromJson(json)
        assertEquals("def456", att.id)
        val revoked = att.revocationStatus as RevocationStatus.Revoked
        assertEquals(1_700_000_100L, revoked.revokedAt)
        assertEquals("compromised", revoked.reason)
        assertEquals("12345", att.platformId)
    }

    @Test
    fun `fromJson parses missing revocation status as Active`() {
        val json = """
            {
                "id": "ghi789",
                "platform": "linkedin.com",
                "platform_handle": "charlie",
                "verification_method": "did:dht:z6Mk...#active",
                "verified_at": 1700000000
            }
        """.trimIndent()
        val att = IdentityAttestation.fromJson(json)
        assertTrue(att.revocationStatus is RevocationStatus.Active)
    }

    @Test
    fun `fromJson rejects unknown revocation_status primitive fail-closed`() {
        // A future Rust-side enum variant (e.g. Suspended) MUST NOT be
        // silently mis-categorized as Active — that would be a
        // security-relevant fail-open default. The parser must throw.
        val json =
            """
            {
                "id": "jkl012",
                "platform": "github.com",
                "platform_handle": "dave",
                "verification_method": "did:dht:z6Mk...#active",
                "verified_at": 1700000000,
                "revocation_status": "Suspended"
            }
            """.trimIndent()
        val err =
            assertFailsWith<IllegalArgumentException> {
                IdentityAttestation.fromJson(json)
            }
        assertTrue(
            err.message?.contains("Unrecognized revocation_status JSON shape") == true,
            "expected fail-closed error message, got: ${err.message}",
        )
    }

    @Test
    fun `fromJson rejects unknown revocation_status object fail-closed`() {
        // A JsonObject that is not {"Revoked": {...}} (e.g. a future
        // {"Suspended": {...}} variant) must also fail closed.
        val json =
            """
            {
                "id": "mno345",
                "platform": "github.com",
                "platform_handle": "eve",
                "verification_method": "did:dht:z6Mk...#active",
                "verified_at": 1700000000,
                "revocation_status": {"Suspended": {"reason": "review"}}
            }
            """.trimIndent()
        assertFailsWith<IllegalArgumentException> {
            IdentityAttestation.fromJson(json)
        }
    }

    @Test
    fun `toString includes key fields`() {
        val att = IdentityAttestation(
            id = "abc123",
            platform = "github.com",
            platformHandle = "alice",
            verificationMethod = "did:dht:z6Mk...#active",
            verifiedAt = 1_700_000_000L,
        )
        val str = att.toString()
        assert(str.contains("abc123"))
        assert(str.contains("github.com"))
        assert(str.contains("alice"))
    }
}
