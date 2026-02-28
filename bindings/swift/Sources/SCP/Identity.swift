import Foundation

// Identity, IdentityProtocol, and related types are now defined by UniFFI in
// ScpBindings.swift.
//
// UniFFI Identity is an open class with methods:
//   - did() -> String
//   - custodyType() -> String
//   - rotateKey() async throws -> Identity
//
// The hand-written IdentityHandle class and Identity struct have been removed.
// Tests should use Identity(noPointer: .init()) for mock instances.
