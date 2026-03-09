import Foundation

// Identity, IdentityProtocol, and related types are defined by UniFFI in
// ScpBindings.swift.
//
// UniFFI Identity is an open class with methods:
//   - did() -> String
//   - custodyType() -> String
//   - rotateKey() async throws -> Identity
//   - hasAgentKey() -> Bool
//   - getAgentPublicKey() -> String?
//   - addAgentKey() async throws -> Identity
//   - removeAgentKey() async throws -> Identity
//   - rotateAgentKey() async throws -> Identity
//
// Standalone UniFFI functions:
//   - identityCreate(_ custody: String) async throws -> Identity
//   - identityCreateWithCustody(_ custody: String) async throws -> Identity
//   - identityLoad(_ did: String) async throws -> Identity
//   - identityResolve(_ did: String) async throws -> String
//
// Tests should use Identity(noPointer: .init()) for mock instances.

// MARK: - IdentityBridge

/// Namespace for UniFFI bridge function references used by identity
/// operations. Each typealias maps 1:1 to a UniFFI-generated function.
/// Closures are injected for testability; defaults call through to
/// ScpBindings.
///
/// See ADR-039 (Agent Key Binding) and spec section 9.
enum IdentityBridge {
    /// Check whether an identity has an agent signing key.
    typealias HasAgentKeyFn = @Sendable (
        _ identity: Identity
    ) -> Bool

    /// Get the agent signing key's public key as a multibase-encoded string.
    typealias GetAgentPublicKeyFn = @Sendable (
        _ identity: Identity
    ) -> String?

    /// Add an agent signing key to an identity.
    typealias AddAgentKeyFn = @Sendable (
        _ identity: Identity
    ) async throws -> Identity

    /// Remove the agent signing key from an identity.
    typealias RemoveAgentKeyFn = @Sendable (
        _ identity: Identity
    ) async throws -> Identity

    /// Rotate the agent signing key for an identity.
    typealias RotateAgentKeyFn = @Sendable (
        _ identity: Identity
    ) async throws -> Identity

    /// Default has agent key function — delegates to UniFFI
    /// ``Identity.hasAgentKey()``.
    static let defaultHasAgentKey: HasAgentKeyFn = { identity in
        identity.hasAgentKey()
    }

    /// Default get agent public key function — delegates to UniFFI
    /// ``Identity.getAgentPublicKey()``.
    static let defaultGetAgentPublicKey: GetAgentPublicKeyFn = { identity in
        identity.getAgentPublicKey()
    }

    /// Default add agent key function — delegates to UniFFI
    /// ``Identity.addAgentKey()``.
    static let defaultAddAgentKey: AddAgentKeyFn = { identity in
        try await identity.addAgentKey()
    }

    /// Default remove agent key function — delegates to UniFFI
    /// ``Identity.removeAgentKey()``.
    static let defaultRemoveAgentKey: RemoveAgentKeyFn = { identity in
        try await identity.removeAgentKey()
    }

    /// Default rotate agent key function — delegates to UniFFI
    /// ``Identity.rotateAgentKey()``.
    static let defaultRotateAgentKey: RotateAgentKeyFn = { identity in
        try await identity.rotateAgentKey()
    }
}

// MARK: - Public API

/// Checks whether an identity has an agent signing key (`#agent` VM).
///
/// Returns `true` if the identity was created with an agent key or if
/// one was added via ``addAgentKeyToIdentity(_:addAgentKeyFn:)``.
///
/// - Parameters:
///   - identity: The identity to check.
///   - hasAgentKeyFn: Bridge function override for testing.
/// - Returns: `true` if the identity has an agent key, `false` otherwise.
///
/// ## Provenance
///
/// - ADR-039 (Agent Key Binding)
/// - Spec section 9
public func identityHasAgentKey(
    _ identity: Identity,
    hasAgentKeyFn: IdentityBridge.HasAgentKeyFn = IdentityBridge.defaultHasAgentKey
) -> Bool {
    hasAgentKeyFn(identity)
}

/// Returns the agent signing key's public key as a multibase-encoded string.
///
/// Returns `nil` if the identity has no agent key or has no retained
/// DID document.
///
/// - Parameters:
///   - identity: The identity to query.
///   - getAgentPublicKeyFn: Bridge function override for testing.
/// - Returns: The multibase-encoded public key, or `nil`.
///
/// ## Provenance
///
/// - ADR-039 (Agent Key Binding)
/// - Spec section 9
public func identityGetAgentPublicKey(
    _ identity: Identity,
    getAgentPublicKeyFn: IdentityBridge.GetAgentPublicKeyFn = IdentityBridge.defaultGetAgentPublicKey
) -> String? {
    getAgentPublicKeyFn(identity)
}

/// Adds an agent signing key to an identity.
///
/// Generates a new Ed25519 keypair for the `#agent` verification method,
/// adds it to the DID document, and publishes the update.
///
/// - Parameters:
///   - identity: The identity to add the agent key to.
///   - addAgentKeyFn: Bridge function override for testing.
/// - Returns: A new ``Identity`` instance with the agent key added.
/// - Throws: ``ScpError`` if the identity already has an agent key or
///   if the operation fails.
///
/// ## Provenance
///
/// - ADR-039 (Agent Key Binding)
/// - Spec section 9
public func addAgentKeyToIdentity(
    _ identity: Identity,
    addAgentKeyFn: IdentityBridge.AddAgentKeyFn = IdentityBridge.defaultAddAgentKey
) async throws -> Identity {
    try await addAgentKeyFn(identity)
}

/// Removes the agent signing key from an identity.
///
/// Removes the `#agent` verification method from the DID document and
/// publishes the update.
///
/// - Parameters:
///   - identity: The identity to remove the agent key from.
///   - removeAgentKeyFn: Bridge function override for testing.
/// - Returns: A new ``Identity`` instance with the agent key removed.
/// - Throws: ``ScpError`` if no agent key exists or removal fails.
///
/// ## Provenance
///
/// - ADR-039 (Agent Key Binding)
/// - Spec section 9
public func removeAgentKeyFromIdentity(
    _ identity: Identity,
    removeAgentKeyFn: IdentityBridge.RemoveAgentKeyFn = IdentityBridge.defaultRemoveAgentKey
) async throws -> Identity {
    try await removeAgentKeyFn(identity)
}

/// Rotates the agent signing key for an identity.
///
/// Generates a new Ed25519 keypair, retires the old `#agent` key as
/// `#retired-agent-{sequence}`, and installs the new key as `#agent`.
///
/// - Parameters:
///   - identity: The identity to rotate the agent key for.
///   - rotateAgentKeyFn: Bridge function override for testing.
/// - Returns: A new ``Identity`` instance with the rotated agent key.
/// - Throws: ``ScpError`` if no agent key exists or rotation fails.
///
/// ## Provenance
///
/// - ADR-039 (Agent Key Binding)
/// - Spec section 9
public func rotateAgentKeyForIdentity(
    _ identity: Identity,
    rotateAgentKeyFn: IdentityBridge.RotateAgentKeyFn = IdentityBridge.defaultRotateAgentKey
) async throws -> Identity {
    try await rotateAgentKeyFn(identity)
}
