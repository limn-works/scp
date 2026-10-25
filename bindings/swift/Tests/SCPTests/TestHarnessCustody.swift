import Foundation
@testable import SCP

// Test-harness custody: the one route by which a test reaches the in-memory
// key store.
//
// Spec section 3.2.2 says an SDK's custody type carries `encrypted_file` and
// `os_keystore` and no other member, and that `in_memory` is a testing-build
// affordance a test harness reaches outside that type. `CustodyType` therefore
// has no in-memory case, and these helpers send the raw string to the UniFFI
// `Scp` that `SCP.inner` wraps.
//
// Only an XCFramework built with the bridge's `testing` feature
// (`build-xcframework.sh --dev`) accepts the string. A release XCFramework
// answers it with `SCP-IDENT-1008` and builds nothing, so a test that calls
// these helpers fails on a shipped build instead of reaching a weaker backend.
//
// This file belongs to the `SCPTests` test target, which the `SCP` library
// product does not contain.

/// The raw custody string a `testing` UniFFI build maps to its in-memory key
/// store (spec section 3.2.2).
let harnessInMemoryCustody = "in_memory"

/// Creates an identity whose keys live in the testing build's in-memory key
/// store.
///
/// `seed` is the ADR-046 cross-bridge parity seed; `nil` lets the in-memory
/// backend draw its keys from the OS RNG.
func createInMemoryIdentity(_ scp: SCP, seed: Data? = nil) async throws -> Identity {
    try await scp.inner.identityCreate(custody: harnessInMemoryCustody, testingSeed: seed)
}

/// Creates an identity carrying an `#agent` signing key (ADR-039) in the
/// testing build's in-memory key store.
func createInMemoryIdentityWithAgentKey(_ scp: SCP) async throws -> Identity {
    try await scp.inner.identityCreateWithAgentKey(custody: harnessInMemoryCustody)
}

/// The `SQLCipher` key every ``persistentTestScp(at:)`` instance opens with.
let persistentTestKey = Data(repeating: 0x5C, count: 32)

/// A fresh directory for a SQLite-backed test instance. Callback custody
/// refuses storage that does not persist (spec section 17.3), so a test that
/// creates an identity with a `KeyCustodyProvider` runs on one. The caller
/// removes it.
func persistentTestDirectory() throws -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("scp-callback-custody-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

/// An instance over `SQLCipher` storage in `dir`.
func persistentTestScp(at dir: URL) throws -> SCP {
    try SCP.withStorage(sqliteDir: dir, key: persistentTestKey)
}

/// The code of the `ScpError` `body` threw, or a description of whatever
/// else happened.
func scpErrorCode(_ body: () async throws -> Void) async -> String {
    do {
        try await body()
        return "no error"
    } catch let error as ScpError {
        switch error {
        case let .Identity(_, code), let .Storage(_, code):
            return code
        default:
            return "other ScpError: \(error)"
        }
    } catch {
        return "non-ScpError: \(error)"
    }
}
