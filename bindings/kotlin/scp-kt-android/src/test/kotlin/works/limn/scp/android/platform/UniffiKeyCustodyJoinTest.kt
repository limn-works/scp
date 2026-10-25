// UniffiKeyCustodyJoinTest.kt — a joiner whose custody is AndroidKeyCustody opens a sealed invitation
//
// Two SCP instances in one JVM: the creator invites, and the joiner, whose identity is created
// through UniffiKeyCustody, reserves a KeyPackage whose HPKE P-256 wrapping key the adapter mints,
// then opens the sealed bundle through the adapter's dhAgree. The instances share one DID resolver
// through the testing export, as two processes sharing the Mainline DHT do.
//
// Provenance: spec 05 §5.12.3.1 (sealed invitation), spec 09 §9.15, spec 17 §17.3 (callback custody
// identity entry), ADR-027 (Android Platform Adapter).

package works.limn.scp.android.platform

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.InviteMemberOutcome
import uniffi.scp.MemoryScope
import uniffi.scp.Scp
import uniffi.scp.ScpException
import uniffi.scp.SqliteKeyMaterial
import uniffi.scp.StorageConfig
import uniffi.scp.testingShareDidResolver
import java.io.File

class UniffiKeyCustodyJoinTest {
    // Callback custody refuses storage that does not persist (spec 17 §17.3), so an instance
    // that creates or loads an identity with a provider runs on SQLCipher storage here.
    @TempDir
    lateinit var dir: File

    private fun sqliteScp(): Scp =
        Scp.withStorage(
            StorageConfig.Sqlite(path = dir.path, key = SqliteKeyMaterial.Raw(key = ByteArray(32) { 0x5c })),
        )

    /** The code of the [ScpException] [body] threw, or a description of whatever else happened. */
    private suspend fun errorCode(body: suspend () -> Unit): String =
        try {
            body()
            "no error"
        } catch (e: ScpException.Identity) {
            e.code
        } catch (e: ScpException.Storage) {
            e.code
        }

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
            val joinerScp = sqliteScp()
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

    @Test
    fun `an identity created with the adapter loads on a new instance with the adapter`() {
        runBlocking {
            val prefs = InMemorySharedPreferences()
            val keystore = JcaFakeKeystoreKeys()
            val first = sqliteScp()
            val did =
                try {
                    val provider = UniffiKeyCustody(AndroidKeyCustody.create(prefs, keystore))
                    first.identityCreateWithCustody(provider = provider).did()
                } finally {
                    first.shutdown(timeoutMillis = 1000uL)
                }

            val second = sqliteScp()
            try {
                assertEquals("SCP-IDENT-1003", errorCode { second.identityLoad(did = did) })
                val custody = AndroidKeyCustody.create(prefs, keystore)
                val loaded = second.identityLoadWithCustody(did = did, provider = UniffiKeyCustody(custody))
                assertEquals(did, loaded.did())
                // A single-admin proposal signs with the identity key the first instance minted.
                val context =
                    second.contextCreate(
                        identity = loaded,
                        params = params.copy(ceiling = listOf("messages:read", "governance:propose", "member:ban")),
                    )
                val response =
                    second.governancePropose(
                        handle = context,
                        proposerDid = did,
                        actionJson = """{"SuspendCapability":{"did":"$did","capabilities":["MessagesWrite"]}}""",
                    )
                assertTrue(response.contains("\"status\":\"Approved\""), response)
                assertEquals(
                    "SCP-IDENT-1008",
                    errorCode { second.identityLoadWithCustody(did = did, provider = UniffiKeyCustody(custody)) },
                )
            } finally {
                second.shutdown(timeoutMillis = 1000uL)
            }
        }
    }

    @Test
    fun `in-memory storage refuses a callback custody create and load`() {
        runBlocking {
            val custody = AndroidKeyCustody.create(InMemorySharedPreferences(), JcaFakeKeystoreKeys())
            val provider = UniffiKeyCustody(custody)
            val scp = Scp.withStorage(StorageConfig.InMemory)
            try {
                assertEquals("SCP-STORAGE-8000", errorCode { scp.identityCreateWithCustody(provider = provider) })
                assertEquals(
                    "SCP-STORAGE-8000",
                    errorCode {
                        scp.identityLoadWithCustody(
                            did = "did:dht:ab3ii3ef4mbcu5rmhkbf5yctwnodzx6a65ghazmtu1ydzhfzezby",
                            provider = provider,
                        )
                    },
                )
            } finally {
                scp.shutdown(timeoutMillis = 1000uL)
            }
        }
    }
}
