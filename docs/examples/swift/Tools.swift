/// Outlet registration, verification, and UCAN minting within a context.
///
/// Demonstrates defining an outlet with JSON schemas and test vectors,
/// registering it in a context, verifying it against those vectors, and
/// minting the UCAN token a caller presents to invoke it.
///
/// The operator's identity comes from a caller-supplied
/// ``KeyCustodyProvider``. ``CustodyType/inMemory`` works only in a build
/// compiled with the `testing` feature.
///
/// Prerequisites:
///   - Add the SCP Swift package to your project
///   - import SCP
///
/// Usage:
///   try await ToolsExample.run(provider: myProvider, storagePassphrase: passphrase)

import Foundation
import SCP

enum ToolsExample {
    static func run(provider: KeyCustodyProvider, storagePassphrase: String) async throws {
        let storageDir = try FileManager.default
            .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            .appendingPathComponent("scp-tools-example")
        let scp = try SCP.withStorage(sqliteDir: storageDir, passphrase: storagePassphrase)

        // 1. Create an identity for the outlet operator.
        let operatorIdentity = try await scp.identityCreateWithCustody(provider: provider)
        print("Operator DID: \(operatorIdentity.did())")

        // 2. Create a context whose ceiling allows registering and invoking Query outlets.
        let params = ContextParams(
            mode: .encrypted,
            ceiling: [
                Capability.Name.messagesRead,
                Capability.Name.outletRegister,
                Capability.Name.outletQueryAll,
            ],
            ceilingPolicy: .immutable,
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 0,
            promotable: false,
            minProtocolVersion: 0,
            maxChainDepth: nil,
            maxNestingDepth: nil,
            sessionCap: nil,
            economicPolicy: nil,
            consequenceRulesJson: nil,
            consequenceConfigJson: nil
        )
        let handle = try await scp.contextCreate(identity: operatorIdentity, params: params)
        print("Context: \(handle.contextId())")

        // 3. Define a calculator outlet with JSON schemas and test vectors.
        let calculator = OutletDefinition(
            name: "calculator",
            description: "A simple arithmetic calculator",
            kind: .query,
            inputSchemaJson: """
            {
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"},
                    "op": {"type": "string", "enum": ["add", "sub", "mul"]}
                },
                "required": ["a", "b", "op"]
            }
            """,
            outputSchemaJson: """
            {
                "type": "object",
                "properties": {"result": {"type": "number"}},
                "required": ["result"]
            }
            """,
            operatorDid: operatorIdentity.did(),
            testVectorsJson: """
            [
                {"input": {"a": 2, "b": 3, "op": "add"}, "expected_output": {"result": 5}, "description": "2 + 3 = 5"},
                {"input": {"a": 7, "b": 3, "op": "mul"}, "expected_output": {"result": 21}, "description": "7 * 3 = 21"}
            ]
            """,
            implementationHash: nil,
            cost: nil
        )

        // 4. Register the outlet. The returned id names it in every later call.
        let outletId = try await scp.outletRegister(handle: handle, definition: calculator)
        print("\nOutlet registered: \(outletId)")

        // 5. Verify the outlet against its test vectors.
        let verification = try await scp.outletVerify(handle: handle, outletId: outletId)
        print("  Verification passed: \(verification.passed)")
        for failure in verification.failures {
            print("    - \(failure)")
        }

        // 6. Mint a UCAN token that authorizes invoking this one Query outlet.
        let token = try await scp.ucanMint(
            handle: handle,
            memberDid: operatorIdentity.did(),
            capabilities: [Capability.outletQuery(outletId)],
            proofs: nil
        )
        print("\nUCAN minted: \(token.tokenId())")
        print("  Capabilities: \(token.capabilities())")

        try await scp.shutdown()
        print("\nOutlet operations complete.")
    }
}
