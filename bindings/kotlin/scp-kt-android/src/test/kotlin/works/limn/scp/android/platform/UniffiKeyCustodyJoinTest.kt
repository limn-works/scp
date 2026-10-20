// UniffiKeyCustodyJoinTest.kt — a joiner whose custody is AndroidKeyCustody opens a sealed invitation
//
// Two SCP instances in one JVM: the creator invites, and the joiner, whose identity is created
// through UniffiKeyCustody, reserves a KeyPackage whose HPKE P-256 wrapping key the adapter mints,
// then opens the sealed bundle through the adapter's dhAgree. The instances share one DID resolver
// through the testing export, as two processes sharing the Mainline DHT do.
//
// Provenance: spec 05 §5.12.3.1 (sealed invitation), spec 09 §9.15, ADR-027 (Android Platform
// Adapter).

package works.limn.scp.android.platform

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.InviteMemberOutcome
import uniffi.scp.MemoryScope
import uniffi.scp.Scp
import uniffi.scp.StorageConfig
import uniffi.scp.testingShareDidResolver

class UniffiKeyCustodyJoinTest {
    private val params =
        ContextParams(
            mode = ContextMode.ENCRYPTED,
            ceiling = listOf("messages:read", "messages:write", "member:invite", "governance:propose"),
            ceilingPolicy = CeilingPolicy.IMMUTABLE,
            governance = GovernanceModel.SINGLE_ADMIN,
            memoryScope = MemoryScope.EPHEMERAL,
            ttlSeconds = 3600uL,
            promotable = false,
            minProtocolVersion = 0.toUShort(),
            maxChainDepth = null,
            maxNestingDepth = null,
            sessionCap = null,
            economicPolicy = null,
            consequenceRulesJson = null,
            consequenceConfigJson = null,
            capabilityRequirementsJson = null,
            pseudonymRotation = null,
        )

    @Test
    fun `a joiner whose custody is the adapter opens a sealed invitation`() {
        runBlocking {
            // Keystore agreement, so the fake counts the agreement the join runs.
            val keystore = JcaFakeKeystoreKeys()
            val custody = AndroidKeyCustody.create(InMemorySharedPreferences(), keystore, keystoreAgreement = true)
            val creatorScp = Scp.withStorage(StorageConfig.InMemory)
            val joinerScp = Scp.withStorage(StorageConfig.InMemory)
            try {
                val creator = creatorScp.identityCreate(custody = "in_memory", testingSeed = null)
                testingShareDidResolver(source = creatorScp, target = joinerScp)
                val joiner = joinerScp.identityCreateWithCustody(provider = UniffiKeyCustody(custody))
                val reservation = joinerScp.reserveKeyPackage(identity = joiner)
                assertTrue(keystore.p256Aliases.isNotEmpty(), "the adapter mints the KeyPackage wrapping key")

                val context = creatorScp.contextCreate(identity = creator, params = params)
                val outcome =
                    creatorScp.inviteMember(
                        identity = creator,
                        contextId = context.contextId(),
                        inviteeDid = joiner.did(),
                        inviteeKeyPackage = reservation.keyPackagePublic,
                    )
                val sealed = (outcome as InviteMemberOutcome.Sealed).bundle
                val joined =
                    joinerScp.contextJoinFromWelcome(
                        identity = joiner,
                        sealed = sealed,
                        reservationId = reservation.reservationId,
                    )

                assertEquals(context.contextId(), joined.contextId())
                assertTrue(keystore.agreeCalls >= 1, "the join must open the seal through the adapter")
            } finally {
                creatorScp.shutdown(timeoutMillis = 1000uL)
                joinerScp.shutdown(timeoutMillis = 1000uL)
            }
        }
    }
}
