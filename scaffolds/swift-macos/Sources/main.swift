/// Minimal SCP macOS app scaffold.
///
/// Passes `AppleKeyCustody`, the SDK's `KeyCustodyProvider` over the Keychain
/// (the `os_keystore` custody request, spec 03 §3.2.2), to
/// `identityCreateWithCustody(provider:)`, then opens an encrypted context.
///
/// A build without the bridge's `testing` feature has no independent next-set
/// substrate, so step 1 throws `SCP-IDENT-1100` in a shipped build. The custody
/// paragraph of `docs/guides/sdk-quickstart.md` states which identity creations
/// a shipped build refuses.

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

// 1. Create a DID identity whose keys the Keychain holds. A shipped build
//    throws `SCP-IDENT-1100` here.
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
    consequenceConfigJson: nil,
    pseudonymRotation: nil
)
let handle = try await scp.contextCreate(identity: identity, params: params)
print("Created context: \(handle.contextId())")

// 3. Close the context and shut the instance down.
try await scp.contextClose(handle: handle, identity: identity)
try await scp.shutdown()
print("Done.")
