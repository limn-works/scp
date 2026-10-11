/// Minimal SCP macOS app scaffold.
///
/// Creates a DID identity through a caller-supplied key custody provider and
/// opens an encrypted context.
///
/// The Swift SDK ships no key store that `identityCreate(custody:)` reaches in
/// a shipped build: its one `CustodyType`, `.inMemory`, works only in a build
/// compiled with the `testing` feature, and a shipped build rejects it with
/// `SCP-IDENT-1008`. Implement `makeKeyCustodyProvider()` over your app's key
/// store before running.

import Foundation
import SCP

enum ScaffoldError: Error {
    /// `makeKeyCustodyProvider()` has not been implemented yet.
    case keyCustodyProviderMissing
    /// `SCP_STORAGE_PASSPHRASE` is not set.
    case storagePassphraseMissing
}

/// Returns the `KeyCustodyProvider` over your app's key store.
func makeKeyCustodyProvider() throws -> KeyCustodyProvider {
    throw ScaffoldError.keyCustodyProviderMissing
}

guard let passphrase = ProcessInfo.processInfo.environment["SCP_STORAGE_PASSPHRASE"] else {
    throw ScaffoldError.storagePassphraseMissing
}
let storageDir = try FileManager.default
    .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    .appendingPathComponent("SCPmacOSApp")
let scp = try SCP.withStorage(sqliteDir: storageDir, passphrase: passphrase)

// 1. Create a DID identity whose keys the provider holds.
let identity = try await scp.identityCreateWithCustody(provider: try makeKeyCustodyProvider())
print("Created identity: \(identity.did())")

// 2. Create an encrypted single-admin context.
let params = ContextParams(
    mode: .encrypted,
    ceiling: ["messages:read", "messages:write", "role:assign"],
    ceilingPolicy: .immutable,
    governance: .singleAdmin,
    memoryScope: .full,
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
let handle = try await scp.contextCreate(identity: identity, params: params)
print("Created context: \(handle.contextId())")

// 3. Close the context and shut the instance down.
try await scp.contextClose(handle: handle, identity: identity)
try await scp.shutdown()
print("Done.")
