/**
 * Outlet registration, verification, and UCAN minting within a context.
 *
 * Demonstrates defining an outlet with JSON schemas and test vectors,
 * registering it in a context, verifying it against those vectors, and
 * minting the UCAN token a caller presents to invoke it.
 *
 * The operator's identity comes from a caller-supplied [KeyCustodyProvider].
 * `CustodyType.IN_MEMORY` works only in a build compiled with the `testing`
 * feature.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   toolsExample(myProvider, File(context.filesDir, "scp-tools"), passphrase)
 */

package works.limn.scp.examples

import kotlinx.coroutines.runBlocking
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.KeyCustodyProvider
import uniffi.scp.MemoryScope
import uniffi.scp.OutletDefinition
import uniffi.scp.OutletKind
import works.limn.scp.SCP
import java.io.File

fun toolsExample(
    provider: KeyCustodyProvider,
    storageDir: File,
    storagePassphrase: String,
) = runBlocking {
    val scp = SCP.withSqlite(storageDir, storagePassphrase)

    // 1. Create an identity for the outlet operator.
    val operator = scp.identityCreateWithCustody(provider)
    println("Operator DID: ${operator.did()}")

    // 2. Create a context whose ceiling allows registering and calling outlets.
    val params =
        ContextParams(
            mode = ContextMode.ENCRYPTED,
            ceiling = listOf("messages:read", "outlet:register", "outlet:call:*"),
            ceilingPolicy = CeilingPolicy.IMMUTABLE,
            governance = GovernanceModel.SINGLE_ADMIN,
            memoryScope = MemoryScope.EPHEMERAL,
            ttlSeconds = 0uL,
            promotable = false,
            minProtocolVersion = 0.toUShort(),
            maxChainDepth = null,
            maxNestingDepth = null,
            sessionCap = null,
            economicPolicy = null,
            consequenceRulesJson = null,
            consequenceConfigJson = null,
        )
    val handle = scp.contextCreate(operator, params)
    println("Context: ${handle.contextId()}")

    // 3. Define a calculator outlet with JSON schemas and test vectors.
    val calculator =
        OutletDefinition(
            name = "calculator",
            description = "A simple arithmetic calculator",
            kind = OutletKind.QUERY,
            inputSchemaJson =
                """
                {
                    "type": "object",
                    "properties": {
                        "a": {"type": "number"},
                        "b": {"type": "number"},
                        "op": {"type": "string", "enum": ["add", "sub", "mul"]}
                    },
                    "required": ["a", "b", "op"]
                }
                """.trimIndent(),
            outputSchemaJson =
                """
                {
                    "type": "object",
                    "properties": {"result": {"type": "number"}},
                    "required": ["result"]
                }
                """.trimIndent(),
            operatorDid = operator.did(),
            testVectorsJson =
                """
                [
                    {"input": {"a": 2, "b": 3, "op": "add"}, "expected_output": {"result": 5}, "description": "2 + 3 = 5"},
                    {"input": {"a": 7, "b": 3, "op": "mul"}, "expected_output": {"result": 21}, "description": "7 * 3 = 21"}
                ]
                """.trimIndent(),
            implementationHash = null,
            cost = null,
        )

    // 4. Register the outlet. The returned id names it in every later call.
    val outletId = scp.outletRegister(handle, calculator)
    println("\nOutlet registered: $outletId")

    // 5. Verify the outlet against its test vectors.
    val verification = scp.outletVerify(handle, outletId)
    println("  Verification passed: ${verification.passed}")
    verification.failures.forEach { println("    - $it") }

    // 6. Mint a UCAN token that authorizes calling this one outlet.
    val token =
        scp.ucanMint(
            handle = handle,
            memberDid = operator.did(),
            capabilities = listOf("outlet:call:$outletId"),
            proofs = null,
        )
    println("\nUCAN minted: ${token.tokenId()}")
    println("  Capabilities: ${token.capabilities()}")

    // SCP.shutdown takes a CoroutineBridge, and the SDK ships no NativeBindings
    // implementation to build one with, so this example cannot shut the
    // instance down. The finalizer logs a warning when the JVM collects it.
    println("\nOutlet operations complete.")
}
