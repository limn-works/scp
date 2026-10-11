/// Minimal SCP macOS app scaffold.
///
/// Creates a DID identity whose keys `AppleKeyCustody` holds in the Keychain
/// (the `os_keystore` custody request, spec 03 §3.2.2) and opens an encrypted
/// context.
///
/// The Swift SDK ships no key store that `identityCreate(custody:)` reaches in
/// a shipped build: its one `CustodyType`, `.inMemory`, works only in a build
/// compiled with the `testing` feature, and a shipped build rejects it with
/// `SCP-IDENT-1008`. `AppleKeyCustody` is the SDK's `KeyCustodyProvider`, which
/// `identityCreateWithCustody(provider:)` takes.

import Foundation
import SCP

enum ScaffoldError: Error {
    /// `SCP_STORAGE_PASSPHRASE` is not set.
    case storagePassphraseMissing
}


guard let passphrase = ProcessInfo.processInfo.environment["SCP_STORAGE_PASSPHRASE"] else {
    throw ScaffoldError.storagePassphraseMissing
}
let storageDir = try FileManager.default
    .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    .appendingPathComponent("SCPmacOSApp")
let scp = try SCP.withStorage(sqliteDir: storageDir, passphrase: passphrase)

// 1. Create a DID identity whose keys the Keychain holds.
let identity = try await scp.identityCreateWithCustody(provider: AppleKeyCustody())
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
