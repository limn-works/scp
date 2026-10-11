// The quick start from `bindings/kotlin/README.md`, copied byte for byte below
// the package line. `ReadmeQuickStartTest` fails when the copy and the README
// block differ, and runs `main()`, so the README block compiles and runs as
// written. Edit both copies together.

package works.limn.scp.quickstart

import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.MemoryScope
import uniffi.scp.StorageConfig
import works.limn.scp.CustodyType
import works.limn.scp.SCP

suspend fun main() {
    // Every call goes through an SCP instance, which takes a required storage backend.
    val scp = SCP(StorageConfig.InMemory)

    // Create a cryptographic identity (DID) whose keys live in $HOME/.scp/keys.bin,
    // sealed under the SCP_KEY_PASSPHRASE environment variable.
    val identity = scp.identityCreate(custody = CustodyType.ENCRYPTED_FILE)
    println("DID: ${identity.did()}")

    // Create an encrypted context that this identity administers.
    val ctx =
        scp.contextCreate(
            identity = identity,
            params =
                ContextParams(
                    mode = ContextMode.ENCRYPTED,
                    ceiling = listOf("messages:read", "messages:write", "context:close"),
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
                ),
        )

    // Send a message (MLS-encrypted, signed, provenance-tagged).
    scp.contextSend(
        handle = ctx,
        identity = identity,
        payload = "Hello from SCP".toByteArray(),
        spendingUcanJwt = null,
    )

    scp.contextClose(handle = ctx, identity = identity)
}
