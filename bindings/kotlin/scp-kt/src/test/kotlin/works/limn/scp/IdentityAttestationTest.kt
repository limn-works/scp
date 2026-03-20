// IdentityAttestationTest.kt — Tests for identity link attestation wrappers (§3.5)

package works.limn.scp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

/**
 * Tests for the [IdentityAttestation] data class and
 * [IdentityAttestationBindings] / [IdentityAttestationBridge] types.
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
            verifiedAt = 1_700_000_000.0,
        )
        assertEquals("abc123", att.id)
        assertEquals("github.com", att.platform)
        assertEquals("alice", att.platformHandle)
        assertEquals("did:dht:z6Mk...#active", att.verificationMethod)
        assertEquals(1_700_000_000.0, att.verifiedAt)
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
            verifiedAt = 1_700_000_000.0,
            revocationStatus = RevocationStatus.Revoked(
                revokedAt = 1_700_000_100.0,
                reason = "compromised",
            ),
            platformId = "12345",
        )
        assertEquals("revoked", att.revocationStatus.status)
        assertEquals("12345", att.platformId)
        val revoked = att.revocationStatus as RevocationStatus.Revoked
        assertEquals(1_700_000_100.0, revoked.revokedAt)
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
            revokedAt = 1_700_000_100.0,
            reason = "test",
        )
        assertEquals("revoked", rs.status)
        assertEquals(1_700_000_100.0, rs.revokedAt)
        assertEquals("test", rs.reason)
    }

    @Test
    fun `RevocationStatus equality`() {
        assertEquals(RevocationStatus.Active, RevocationStatus.Active)
        assertEquals(
            RevocationStatus.Revoked(revokedAt = 1.0, reason = "a"),
            RevocationStatus.Revoked(revokedAt = 1.0, reason = "a"),
        )
        assertNotEquals(
            RevocationStatus.Active as RevocationStatus,
            RevocationStatus.Revoked(revokedAt = 1.0) as RevocationStatus,
        )
    }

    @Test
    fun equality() {
        val att1 = IdentityAttestation(
            id = "abc123",
            platform = "github.com",
            platformHandle = "alice",
            verificationMethod = "did:dht:z6Mk...#active",
            verifiedAt = 1_700_000_000.0,
        )
        val att2 = IdentityAttestation(
            id = "abc123",
            platform = "github.com",
            platformHandle = "alice",
            verificationMethod = "did:dht:z6Mk...#active",
            verifiedAt = 1_700_000_000.0,
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
            verifiedAt = 1_700_000_000.0,
        )
        val att2 = IdentityAttestation(
            id = "def456",
            platform = "github.com",
            platformHandle = "alice",
            verificationMethod = "did:dht:z6Mk...#active",
            verifiedAt = 1_700_000_000.0,
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
            verifiedAt = 1_700_000_000.0,
            platformId = "42",
        )
        val renewed = att.copy(verifiedAt = 1_800_000_000.0)
        assertEquals("abc123", renewed.id)
        assertEquals(1_800_000_000.0, renewed.verifiedAt)
        assertEquals("42", renewed.platformId)
    }

    @Test
    fun `toString includes key fields`() {
        val att = IdentityAttestation(
            id = "abc123",
            platform = "github.com",
            platformHandle = "alice",
            verificationMethod = "did:dht:z6Mk...#active",
            verifiedAt = 1_700_000_000.0,
        )
        val str = att.toString()
        assert(str.contains("abc123"))
        assert(str.contains("github.com"))
        assert(str.contains("alice"))
    }
}
