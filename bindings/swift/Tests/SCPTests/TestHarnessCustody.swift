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
