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
    /// Create a new identity with the specified custody method.
    typealias CreateFn = @Sendable (
        _ custody: String
    ) async throws -> Identity

    /// Load an existing identity by DID.
    typealias LoadFn = @Sendable (
        _ did: String
    ) async throws -> Identity

    /// Resolve a DID to its document.
    typealias ResolveFn = @Sendable (
        _ did: String
    ) async throws -> DidDocument

    /// Default create function — delegates to UniFFI
    /// ``identityCreate(custody:)``.
    static let defaultCreate: CreateFn = { custody in
        try await identityCreate(custody: custody)
    }

    /// Default load function — delegates to UniFFI
    /// ``identityLoad(did:)``.
    static let defaultLoad: LoadFn = { did in
        try await identityLoad(did: did)
    }

    /// Default resolve function — delegates to UniFFI
    /// ``identityResolve(did:)``.
    static let defaultResolve: ResolveFn = { did in
        try await identityResolve(did: did)
    }

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

    /// Generate a device attestation token for an identity.
    typealias AttestDeviceFn = @Sendable (
        _ identity: Identity
    ) async throws -> String

    /// Verify a device attestation token.
    typealias VerifyDeviceAttestationFn = @Sendable (
        _ did: String,
        _ tokenBase64: String
    ) async throws -> Bool

    /// Default attest device function — delegates to UniFFI
    /// ``identityAttestDevice(identity:)``.
    static let defaultAttestDevice: AttestDeviceFn = { identity in
        try await identityAttestDevice(identity: identity)
    }

    /// Default verify device attestation function — delegates to UniFFI
    /// ``identityVerifyDeviceAttestation(did:tokenBase64:)``.
    static let defaultVerifyDeviceAttestation: VerifyDeviceAttestationFn = { did, tokenBase64 in
        try await identityVerifyDeviceAttestation(did: did, tokenBase64: tokenBase64)
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

/// Generates a device attestation token for an identity.
///
/// Uses the platform's device attestation mechanism to produce a token
/// proving the identity is bound to a physical device. The token is
/// base64-encoded for transport.
///
/// - Parameters:
///   - identity: The identity to attest. Must have been created via
///     ``identityCreate`` (not ``identityLoad``).
///   - attestDeviceFn: Bridge function override for testing.
/// - Returns: A base64-encoded attestation token string.
/// - Throws: ``ScpError`` if the identity was externally loaded or
///   attestation generation fails.
///
/// ## Provenance
///
/// - Spec section 9.3 (Sybil Resistance and Identity Uniqueness)
public func identityAttestDevice(
    _ identity: Identity,
    attestDeviceFn: IdentityBridge.AttestDeviceFn = IdentityBridge.defaultAttestDevice
) async throws -> String {
    try await attestDeviceFn(identity)
}

/// Verifies a device attestation token.
///
/// Checks that the base64-encoded attestation token is valid. The DID
/// parameter is provided for API consistency (future use for binding
/// verification).
///
/// - Parameters:
///   - did: The DID string associated with the attestation.
///   - tokenBase64: The base64-encoded attestation token to verify.
///   - verifyDeviceAttestationFn: Bridge function override for testing.
/// - Returns: `true` if the token is valid, `false` otherwise.
/// - Throws: ``ScpError`` if base64 decoding fails or verification
///   encounters an error.
///
/// ## Provenance
///
/// - Spec section 9.3 (Sybil Resistance and Identity Uniqueness)
public func identityVerifyDeviceAttestation(
    did: String,
    tokenBase64: String,
    verifyDeviceAttestationFn: IdentityBridge.VerifyDeviceAttestationFn =
        IdentityBridge.defaultVerifyDeviceAttestation
) async throws -> Bool {
    try await verifyDeviceAttestationFn(did, tokenBase64)
}

/// Creates a new SCP identity with the specified custody method.
///
/// Delegates to the UniFFI ``identityCreate(custody:)`` bridge function.
/// The custody method determines where private key material is stored:
///
/// - `"in_memory"` — Heap memory (dev/test only). Requires the
///   `allow_in_memory_custody` feature.
/// - `"platform"` — Secure Enclave (iOS) or Android Keystore (Android).
///   Requires ``identityCreateWithCustody`` with a platform provider.
///
/// - Parameters:
///   - custody: The custody method string (`"in_memory"` or `"platform"`).
///   - createFn: Bridge function override for testing.
/// - Returns: A new ``Identity`` instance.
/// - Throws: ``ScpError/Identity(message:code:)`` if creation fails.
///
/// ## Provenance
///
/// - ADR-006 (Platform Abstraction)
/// - Spec section 9 (Identity)
public func createIdentity(
    custody: String,
    createFn: IdentityBridge.CreateFn = IdentityBridge.defaultCreate
) async throws -> Identity {
    try await createFn(custody)
}

/// Loads an existing SCP identity from storage by its DID.
///
/// Delegates to the UniFFI ``identityLoad(did:)`` bridge function.
/// The returned identity is a DID-string-only handle without local key
/// material. Key operations require a custody provider to be wired.
///
/// - Parameters:
///   - did: The DID string to load (e.g., `"did:dht:z6Mk..."`).
///   - loadFn: Bridge function override for testing.
/// - Returns: An ``Identity`` handle for the loaded DID.
/// - Throws: ``ScpError/Identity(message:code:)`` if the DID format is
///   unsupported or the identity cannot be loaded.
///
/// ## Provenance
///
/// - ADR-006 (Platform Abstraction)
/// - Spec section 9 (Identity)
public func loadIdentity(
    did: String,
    loadFn: IdentityBridge.LoadFn = IdentityBridge.defaultLoad
) async throws -> Identity {
    try await loadFn(did)
}

/// Resolves a DID to its document.
///
/// Delegates to the UniFFI ``identityResolve(did:)`` bridge function.
/// Performs DHT resolution and returns the document fields.
///
/// - Parameters:
///   - did: The DID string to resolve (e.g., `"did:dht:z6Mk..."`).
///   - resolveFn: Bridge function override for testing.
/// - Returns: A ``DidDocument`` with the resolved document fields.
/// - Throws: ``ScpError/Identity(message:code:)`` if the DID cannot be
///   resolved (not found on DHT, invalid format, verification failure).
///
/// ## Provenance
///
/// - ADR-002 (DID)
/// - Spec section 3 (Identity)
public func resolveIdentity(
    did: String,
    resolveFn: IdentityBridge.ResolveFn = IdentityBridge.defaultResolve
) async throws -> DidDocument {
    try await resolveFn(did)
}
