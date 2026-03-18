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
//   - identityCreateWithCustody(_ provider: KeyCustodyProvider) async throws -> Identity
//   - identityCreateWithAgentKey(_ custody: String) async throws -> Identity
//   - identityMigrate(_ identity: Identity) async throws -> Identity
//   - identityLoad(_ did: String) async throws -> Identity
//   - identityResolve(_ did: String) async throws -> DidDocument
//
// Tests should use Identity(noPointer: .init()) for mock instances.

// MARK: - IdentityBridge

/// Namespace for UniFFI bridge function references used by identity
/// operations. Each typealias maps 1:1 to a UniFFI-generated function.
/// Closures are injected for testability; defaults call through to
/// ScpBindings.
///
/// See ADR-039 (Agent Key Binding) and spec section 9.
public enum IdentityBridge {
    /// Create a new identity with the specified custody method.
    public typealias CreateFn = @Sendable (
        _ custody: String
    ) async throws -> Identity

    /// Load an existing identity by DID.
    public typealias LoadFn = @Sendable (
        _ did: String
    ) async throws -> Identity

    /// Resolve a DID to its document.
    public typealias ResolveFn = @Sendable (
        _ did: String
    ) async throws -> DidDocument

    /// Default create function — delegates to UniFFI
    /// ``identityCreate(custody:)``.
    public static let defaultCreate: CreateFn = { custody in
        try await identityCreate(custody: custody)
    }

    /// Default load function — delegates to UniFFI
    /// ``identityLoad(did:)``.
    public static let defaultLoad: LoadFn = { did in
        try await identityLoad(did: did)
    }

    /// Default resolve function — delegates to UniFFI
    /// ``identityResolve(did:)``.
    public static let defaultResolve: ResolveFn = { did in
        try await identityResolve(did: did)
    }

    /// Check whether an identity has an agent signing key.
    public typealias HasAgentKeyFn = @Sendable (
        _ identity: Identity
    ) -> Bool

    /// Get the agent signing key's public key as a multibase-encoded string.
    public typealias GetAgentPublicKeyFn = @Sendable (
        _ identity: Identity
    ) -> String?

    /// Add an agent signing key to an identity.
    public typealias AddAgentKeyFn = @Sendable (
        _ identity: Identity
    ) async throws -> Identity

    /// Remove the agent signing key from an identity.
    public typealias RemoveAgentKeyFn = @Sendable (
        _ identity: Identity
    ) async throws -> Identity

    /// Rotate the agent signing key for an identity.
    public typealias RotateAgentKeyFn = @Sendable (
        _ identity: Identity
    ) async throws -> Identity

    /// Default has agent key function — delegates to UniFFI
    /// ``Identity.hasAgentKey()``.
    public static let defaultHasAgentKey: HasAgentKeyFn = { identity in
        identity.hasAgentKey()
    }

    /// Default get agent public key function — delegates to UniFFI
    /// ``Identity.getAgentPublicKey()``.
    public static let defaultGetAgentPublicKey: GetAgentPublicKeyFn = { identity in
        identity.getAgentPublicKey()
    }

    /// Default add agent key function — delegates to UniFFI
    /// ``Identity.addAgentKey()``.
    public static let defaultAddAgentKey: AddAgentKeyFn = { identity in
        try await identity.addAgentKey()
    }

    /// Default remove agent key function — delegates to UniFFI
    /// ``Identity.removeAgentKey()``.
    public static let defaultRemoveAgentKey: RemoveAgentKeyFn = { identity in
        try await identity.removeAgentKey()
    }

    /// Default rotate agent key function — delegates to UniFFI
    /// ``Identity.rotateAgentKey()``.
    public static let defaultRotateAgentKey: RotateAgentKeyFn = { identity in
        try await identity.rotateAgentKey()
    }

    /// Create a new identity with an agent key.
    public typealias CreateWithAgentKeyFn = @Sendable (
        _ custody: String
    ) async throws -> Identity

    /// Migrate an identity to a new DID.
    public typealias MigrateFn = @Sendable (
        _ identity: Identity
    ) async throws -> Identity

    /// Default create with agent key function — delegates to UniFFI
    /// ``identityCreateWithAgentKey(custody:)``.
    public static let defaultCreateWithAgentKey: CreateWithAgentKeyFn = { custody in
        try await identityCreateWithAgentKey(custody: custody)
    }

    /// Default migrate function — delegates to UniFFI
    /// ``identityMigrate(identity:)``.
    public static let defaultMigrate: MigrateFn = { identity in
        try await identityMigrate(identity: identity)
    }

    /// Generate a device attestation token for an identity.
    public typealias AttestDeviceFn = @Sendable (
        _ identity: Identity
    ) async throws -> String

    /// Verify a device attestation token.
    public typealias VerifyDeviceAttestationFn = @Sendable (
        _ did: String,
        _ tokenBase64: String
    ) async throws -> Bool

    /// Default attest device function — delegates to UniFFI
    /// ``identityAttestDevice(identity:)``.
    public static let defaultAttestDevice: AttestDeviceFn = { identity in
        try await identityAttestDevice(identity: identity)
    }

    /// Default verify device attestation function — delegates to UniFFI
    /// ``identityVerifyDeviceAttestation(did:tokenBase64:)``.
    public static let defaultVerifyDeviceAttestation: VerifyDeviceAttestationFn = { did, tokenBase64 in
        try await identityVerifyDeviceAttestation(did: did, tokenBase64: tokenBase64)
    }

    /// Execute the compromise recovery protocol for an identity.
    public typealias ExecuteRecoveryFn = @Sendable (
        _ did: String,
        _ tier: String,
        _ contextIds: [String]
    ) async throws -> String

    /// Execute the custody migration protocol for an identity.
    public typealias ExecuteCustodyMigrationFn = @Sendable (
        _ did: String,
        _ target: String,
        _ contextIds: [String]
    ) async throws -> String

    /// Default execute recovery function — delegates to UniFFI
    /// ``identityExecuteRecovery(did:tier:contextIds:)``.
    public static let defaultExecuteRecovery: ExecuteRecoveryFn = { did, tier, contextIds in
        try await identityExecuteRecovery(did: did, tier: tier, contextIds: contextIds)
    }

    /// Default execute custody migration function — delegates to UniFFI
    /// ``identityExecuteCustodyMigration(did:target:contextIds:)``.
    public static let defaultExecuteCustodyMigration: ExecuteCustodyMigrationFn = { did, target, contextIds in
        try await identityExecuteCustodyMigration(did: did, target: target, contextIds: contextIds)
    }

    // MARK: Identity Link Attestation (§3.5.1)

    /// Create an identity link attestation.
    public typealias CreateLinkAttestationFn = @Sendable (
        _ identity: Identity,
        _ platform: String,
        _ handle: String,
        _ proof: String,
        _ verificationMethod: String,
        _ platformId: String?
    ) async throws -> String

    /// List identity link attestations.
    public typealias LinkAttestationsFn = @Sendable (
        _ did: String
    ) throws -> String

    /// Remove an identity link attestation.
    public typealias RemoveLinkAttestationFn = @Sendable (
        _ did: String,
        _ attestationId: String
    ) -> Bool

    /// Verify an identity link attestation.
    public typealias VerifyLinkAttestationFn = @Sendable (
        _ attestationJson: String
    ) async throws -> Bool

    /// Default create link attestation — delegates to UniFFI.
    public static let defaultCreateLinkAttestation: CreateLinkAttestationFn = { identity, platform, handle, proof, method, platformId in
        try await identityCreateLinkAttestation(identity: identity, platform: platform, handle: handle, proof: proof, verificationMethod: method, platformId: platformId)
    }

    /// Default link attestations — delegates to UniFFI.
    public static let defaultLinkAttestations: LinkAttestationsFn = { did in
        try identityLinkAttestations(did: did)
    }

    /// Default remove link attestation — delegates to UniFFI.
    public static let defaultRemoveLinkAttestation: RemoveLinkAttestationFn = { did, attestationId in
        identityRemoveLinkAttestation(did: did, attestationId: attestationId)
    }

    /// Default verify link attestation — delegates to UniFFI.
    public static let defaultVerifyLinkAttestation: VerifyLinkAttestationFn = { json in
        try await identityVerifyLinkAttestation(attestationJson: json)
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
/// - Throws: ``ScpError/Identity(msg:code:)`` if creation fails.
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
/// - Throws: ``ScpError/Identity(msg:code:)`` if the DID format is
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
/// - Throws: ``ScpError/Identity(msg:code:)`` if the DID cannot be
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

/// Creates a new SCP identity with an agent signing key (ADR-039).
///
/// Creates a DID identity with both the standard signing key and an
/// `#agent` verification method in the DID document. The agent key
/// allows agent-bound operations without exposing the primary identity key.
///
/// - Parameters:
///   - custody: The custody method string (`"in_memory"` or `"platform"`).
///   - createWithAgentKeyFn: Bridge function override for testing.
/// - Returns: A new ``Identity`` instance with an agent key.
/// - Throws: ``ScpError/Identity(msg:code:)`` if creation fails.
///
/// ## Provenance
///
/// - ADR-039 (Agent Key Binding)
/// - Spec section 9 (Identity)
public func createIdentityWithAgentKey(
    custody: String,
    createWithAgentKeyFn: IdentityBridge.CreateWithAgentKeyFn = IdentityBridge.defaultCreateWithAgentKey
) async throws -> Identity {
    try await createWithAgentKeyFn(custody)
}

/// Migrates an identity to a new DID (Layer 2 rotation).
///
/// Creates a new DID using the pre-rotation key as the new Identity Key.
/// The old DID document is updated with an `alsoKnownAs` entry pointing
/// to the new DID, creating a verifiable migration chain.
///
/// - Parameters:
///   - identity: The identity to migrate.
///   - migrateFn: Bridge function override for testing.
/// - Returns: A new ``Identity`` with the migrated DID.
/// - Throws: ``ScpError/Identity(msg:code:)`` if the identity is
///   not in the registry or migration fails.
///
/// ## Provenance
///
/// - Spec section 3 (Identity), section 9.2 (Key Rotation)
public func migrateIdentity(
    _ identity: Identity,
    migrateFn: IdentityBridge.MigrateFn = IdentityBridge.defaultMigrate
) async throws -> Identity {
    try await migrateFn(identity)
}

// MARK: - Recovery and Custody Migration

/// Executes the compromise recovery protocol for an identity.
///
/// Runs the 6-step recovery protocol from spec section 9.12.
///
/// - Parameters:
///   - did: The DID string to recover.
///   - tier: Compromise tier: `"agent"`, `"active_signing"`, or `"identity_key"`.
///   - contextIds: Context IDs where this DID is a member.
///   - executeRecoveryFn: Bridge function override for testing.
/// - Returns: JSON string with the recovery result.
/// - Throws: ``ScpError/Identity(msg:code:)`` if recovery fails.
///
/// ## Provenance
///
/// - Spec section 9.12 (Compromise Recovery)
public func executeRecovery(
    did: String,
    tier: String,
    contextIds: [String] = [],
    executeRecoveryFn: IdentityBridge.ExecuteRecoveryFn = IdentityBridge.defaultExecuteRecovery
) async throws -> String {
    try await executeRecoveryFn(did, tier, contextIds)
}

/// Executes the custody migration protocol for an identity.
///
/// Runs the 5-step migration protocol from spec section 3.2.1.
///
/// - Parameters:
///   - did: The DID string to migrate.
///   - target: Target custody type: `"platform_managed"`, `"hardware"`,
///     `"software"`, or `"in_memory"`.
///   - contextIds: Context IDs where this DID is a member.
///   - executeCustodyMigrationFn: Bridge function override for testing.
/// - Returns: JSON string with the migration result.
/// - Throws: ``ScpError/Identity(msg:code:)`` if migration fails.
///
/// ## Provenance
///
/// - Spec section 3.2.1 (Key Custody Migration Protocol)
public func executeCustodyMigration(
    did: String,
    target: String,
    contextIds: [String] = [],
    executeCustodyMigrationFn: IdentityBridge.ExecuteCustodyMigrationFn =
        IdentityBridge.defaultExecuteCustodyMigration
) async throws -> String {
    try await executeCustodyMigrationFn(did, target, contextIds)
}

// MARK: - Identity Link Attestation (§3.5.1)

/// Creates an identity link attestation for an external platform identity.
///
/// - Parameters:
///   - identity: The identity to attest.
///   - platform: Platform identifier (e.g., `"github.com"`).
///   - handle: Handle on the platform (e.g., `"@alice"`).
///   - proof: Method-specific proof data.
///   - verificationMethod: One of `"oauth"`, `"signed_post"`, `"dns_record"`,
///     or `"challenge_response"`.
///   - platformId: Optional immutable platform user ID.
///   - createLinkAttestationFn: Bridge function override for testing.
/// - Returns: JSON string of the created attestation.
/// - Throws: ``ScpError/Identity(msg:code:)`` if signing fails.
///
/// ## Provenance
///
/// - Spec section 3.5.1 (Identity Link Attestation)
public func createIdentityLinkAttestation(
    identity: Identity,
    platform: String,
    handle: String,
    proof: String,
    verificationMethod: String = "oauth",
    platformId: String? = nil,
    createLinkAttestationFn: IdentityBridge.CreateLinkAttestationFn =
        IdentityBridge.defaultCreateLinkAttestation
) async throws -> String {
    try await createLinkAttestationFn(identity, platform, handle, proof, verificationMethod, platformId)
}

/// Lists all identity link attestations for a DID.
///
/// - Parameters:
///   - did: The DID string.
///   - linkAttestationsFn: Bridge function override for testing.
/// - Returns: JSON array string of attestation objects.
///
/// ## Provenance
///
/// - Spec section 3.5.1 (Identity Link Attestation)
public func identityLinkAttestationsList(
    did: String,
    linkAttestationsFn: IdentityBridge.LinkAttestationsFn =
        IdentityBridge.defaultLinkAttestations
) throws -> String {
    try linkAttestationsFn(did)
}

/// Removes an identity link attestation by its ID.
///
/// - Parameters:
///   - did: The DID string.
///   - attestationId: The deterministic attestation ID to remove.
///   - removeLinkAttestationFn: Bridge function override for testing.
/// - Returns: `true` if found and removed.
///
/// ## Provenance
///
/// - Spec section 3.5.1 (Identity Link Attestation)
public func removeIdentityLinkAttestation(
    did: String,
    attestationId: String,
    removeLinkAttestationFn: IdentityBridge.RemoveLinkAttestationFn =
        IdentityBridge.defaultRemoveLinkAttestation
) -> Bool {
    removeLinkAttestationFn(did, attestationId)
}

/// Verifies the Ed25519 signature on an identity link attestation.
///
/// - Parameters:
///   - attestationJson: JSON string of the attestation.
///   - verifyLinkAttestationFn: Bridge function override for testing.
/// - Returns: `true` if the signature is valid.
///
/// ## Provenance
///
/// - Spec section 3.5.1 (Identity Link Attestation)
public func verifyIdentityLinkAttestation(
    attestationJson: String,
    verifyLinkAttestationFn: IdentityBridge.VerifyLinkAttestationFn =
        IdentityBridge.defaultVerifyLinkAttestation
) async throws -> Bool {
    try await verifyLinkAttestationFn(attestationJson)
}
