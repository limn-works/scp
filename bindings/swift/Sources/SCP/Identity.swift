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
//   - identityCreateLinkAttestation(identity:platform:handle:proof:verificationMethod:platformId:) async throws -> String
//   - identityLinkAttestations(did:) throws -> String
//   - identityRemoveLinkAttestation(did:attestationId:) -> Bool
//   - identityVerifyLinkAttestation(attestationJson:issuerPublicKeyHex:) async throws -> Bool
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
    ///
    /// The optional `seed` parameter is a 32-byte deterministic seed for
    /// the `in_memory` custody path only (ADR-046 parity harness). In
    /// production use, pass `nil` to get OS RNG entropy.
    public typealias CreateFn = @Sendable (
        _ custody: String,
        _ seed: Data?
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
    /// ``identityCreate(custody:seed:)``.
    public static let defaultCreate: CreateFn = { custody, seed in
        try await identityCreate(custody: custody, seed: seed)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
/// Delegates to the UniFFI ``identityCreate(custody:seed:)`` bridge
/// function. The custody method determines where private key material
/// is stored:
///
/// - `"in_memory"` — Heap memory (dev/test only). Requires the
///   `allow_in_memory_custody` feature.
/// - `"platform"` — Secure Enclave (iOS) or Android Keystore (Android).
///   Requires ``identityCreateWithCustody`` with a platform provider.
///
/// - Parameters:
///   - custody: The custody method string (`"in_memory"` or `"platform"`).
///   - seed: Optional 32-byte deterministic seed for `in_memory` custody.
///       Pass `nil` in production — OS RNG entropy is used. Non-nil seeds
///       are validated to be exactly 32 bytes; any other length is a
///       validation error (SCP-VALID-7007). Only the `in_memory` custody
///       path honors the seed (ADR-046 parity harness).
///   - createFn: Bridge function override for testing.
/// - Returns: A new ``Identity`` instance.
/// - Throws: ``ScpError/Identity(msg:code:)`` if creation fails.
///
/// ## Provenance
///
/// - ADR-006 (Platform Abstraction)
/// - ADR-046 (Deterministic parity harness)
/// - Spec section 9 (Identity)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func createIdentity(
    custody: String,
    seed: Data? = nil,
    createFn: IdentityBridge.CreateFn = IdentityBridge.defaultCreate
) async throws -> Identity {
    try await createFn(custody, seed)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func executeCustodyMigration(
    did: String,
    target: String,
    contextIds: [String] = [],
    executeCustodyMigrationFn: IdentityBridge.ExecuteCustodyMigrationFn =
        IdentityBridge.defaultExecuteCustodyMigration
) async throws -> String {
    try await executeCustodyMigrationFn(did, target, contextIds)
}

// MARK: - RevocationStatus

/// Revocation status for an identity attestation (§3.5).
///
/// Mirrors the Rust `RevocationStatus` enum:
///
/// - `Active` -> `.active`
/// - `Revoked { revoked_at, reason }` -> `.revoked(revokedAt:reason:)`
///
/// ## Provenance
///
/// - Spec section 3.5 (Identity Link Attestations)
public enum RevocationStatus: Sendable, Equatable {
    /// The attestation is active and valid.
    case active

    /// The attestation has been revoked.
    ///
    /// - Parameters:
    ///   - revokedAt: Unix timestamp (seconds) when the attestation was revoked.
    ///   - reason: Optional human-readable revocation reason.
    case revoked(revokedAt: UInt64, reason: String? = nil)

    /// The status string: `"active"` or `"revoked"`. Internal — use pattern matching.
    var status: String {
        switch self {
        case .active:
            return "active"
        case .revoked:
            return "revoked"
        }
    }

    /// Unix timestamp (seconds) when the attestation was revoked.
    /// Returns `nil` for active attestations.
    public var revokedAt: UInt64? {
        switch self {
        case .active:
            return nil
        case let .revoked(revokedAt, _):
            return revokedAt
        }
    }

    /// Optional human-readable revocation reason.
    /// Returns `nil` for active attestations.
    public var reason: String? {
        switch self {
        case .active:
            return nil
        case let .revoked(_, reason):
            return reason
        }
    }
}

// MARK: - IdentityAttestation

/// An identity link attestation binding a DID to an external platform (§3.5).
///
/// Represents a cryptographically signed claim that the DID owner also
/// controls an identity on an external platform (e.g., GitHub, X, LinkedIn).
///
/// The ``id`` is deterministically derived as
/// `hex(SHA-256(issuer || platform || handle || issued_at))`.
public struct IdentityAttestation: Sendable, Equatable {
    /// Deterministic attestation ID.
    public let id: String

    /// Platform identifier (e.g., `"github.com"`).
    public let platform: String

    /// Platform handle or username.
    public let platformHandle: String

    /// DID verification method that signed this attestation.
    public let verificationMethod: String

    /// Unix timestamp (seconds) when the evidence was last verified.
    public let verifiedAt: UInt64

    /// Revocation status.
    public let revocationStatus: RevocationStatus

    /// Optional platform-assigned unique identifier.
    public let platformId: String?

    /// Raw JSON string from the bridge for roundtrip signature verification.
    ///
    /// `nil` for attestations constructed manually (not from the bridge).
    /// Stored as a JSON string (not `[String: Any]`) to maintain `Sendable`
    /// conformance.
    public let rawJson: String?

    /// Creates an attestation from its component fields.
    public init(
        id: String,
        platform: String,
        platformHandle: String,
        verificationMethod: String,
        verifiedAt: UInt64,
        revocationStatus: RevocationStatus = .active,
        platformId: String? = nil,
        rawJson: String? = nil
    ) {
        self.id = id
        self.platform = platform
        self.platformHandle = platformHandle
        self.verificationMethod = verificationMethod
        self.verifiedAt = verifiedAt
        self.revocationStatus = revocationStatus
        self.platformId = platformId
        self.rawJson = rawJson
    }

    /// Verifies this attestation's signature and validity.
    ///
    /// Delegates to the bridge's trust verification function.
    ///
    /// The issuer's public key cannot be reliably extracted from the DID string
    /// because attestations are signed with `#active` or `#agent` keys
    /// (spec section 3.5.2), not the `#0` identity key embedded in the DID.
    ///
    /// - Parameters:
    ///   - issuerPublicKeyHex: Hex-encoded Ed25519 public key of the issuer.
    ///   - verifyFn: Bridge function override for testing.
    /// - Returns: `true` if the attestation is valid.
    /// - Throws: ``ScpError`` if verification is not available.
    ///
    /// ## Provenance
    ///
    /// - Spec section 3.5 (Identity Link Attestations)
    public func verify(
        issuerPublicKeyHex: String,
        verifyFn: IdentityAttestationBridge.VerifyFn = IdentityAttestationBridge.defaultVerify
    ) async throws -> Bool {
        try await verifyFn(self, issuerPublicKeyHex)
    }
}

// MARK: - Identity Attestation Bridge

/// Namespace for identity link attestation bridge function references.
///
/// Defaults delegate to UniFFI-generated free functions for attestation
/// CRUD. The UniFFI bridge returns JSON strings that are parsed into
/// ``IdentityAttestation`` values via the private ``AttestationWire``
/// Codable type.
///
/// ## Provenance
///
/// - Spec section 3.5 (Identity Link Attestations)
public enum IdentityAttestationBridge {
    /// Create an identity link attestation.
    public typealias CreateFn = @Sendable (
        _ did: String,
        _ platform: String,
        _ handle: String,
        _ proof: String,
        _ verificationMethod: String,
        _ platformId: String?
    ) async throws -> IdentityAttestation

    /// List attestations for an identity.
    public typealias ListFn = @Sendable (
        _ did: String
    ) async throws -> [IdentityAttestation]

    /// Remove an attestation by ID.
    public typealias RemoveFn = @Sendable (
        _ did: String,
        _ attestationId: String
    ) async throws -> Bool

    /// Default create function — delegates to UniFFI
    /// ``identityCreateLinkAttestation(identity:platform:handle:proof:verificationMethod:platformId:)``.
    ///
    /// Loads the ``Identity`` from the DID string via ``identityLoad(did:)``,
    /// then calls the UniFFI create function and parses the JSON result.
    public static let defaultCreate: CreateFn = { did, platform, handle, proof, verificationMethod, platformId in
        let identity = try await identityLoad(did: did)
        let json = try await identityCreateLinkAttestation(
            identity: identity,
            platform: platform,
            handle: handle,
            proof: proof,
            verificationMethod: verificationMethod,
            platformId: platformId
        )
        return try AttestationWire.parseAttestation(from: json)
    }

    /// Default list function — delegates to UniFFI
    /// ``identityLinkAttestations(did:)``.
    ///
    /// Calls the UniFFI list function and parses the JSON array result.
    public static let defaultList: ListFn = { did in
        let json = try identityLinkAttestations(did: did)
        return try AttestationWire.parseAttestations(from: json)
    }

    /// Default remove function — delegates to UniFFI
    /// ``identityRemoveLinkAttestation(did:attestationId:)``.
    public static let defaultRemove: RemoveFn = { did, attestationId in
        identityRemoveLinkAttestation(did: did, attestationId: attestationId)
    }

    /// Verify an attestation's signature and validity.
    ///
    /// The issuer's public key cannot be reliably extracted from the DID string
    /// because attestations are signed with `#active` or `#agent` keys
    /// (spec section 3.5.2), not the `#0` identity key embedded in the DID.
    public typealias VerifyFn = @Sendable (
        _ attestation: IdentityAttestation,
        _ issuerPublicKeyHex: String
    ) async throws -> Bool

    /// Default verify function — delegates to UniFFI
    /// ``identityVerifyLinkAttestation(attestationJson:issuerPublicKeyHex:)``.
    ///
    /// Uses ``IdentityAttestation/rawJson`` when available for exact
    /// roundtrip fidelity. Falls back to re-serializing the attestation
    /// if ``rawJson`` is `nil`.
    public static let defaultVerify: VerifyFn = { attestation, issuerPublicKeyHex in
        let json: String
        if let raw = attestation.rawJson {
            json = raw
        } else {
            json = try AttestationWire.serializeAttestation(attestation)
        }
        return try await identityVerifyLinkAttestation(
            attestationJson: json,
            issuerPublicKeyHex: issuerPublicKeyHex
        )
    }
}

// MARK: - Attestation JSON Wire Format

/// Private Codable claim matching Rust `AttestationClaim` JSON.
private struct AttestationClaimWire: Codable {
    let platform: String
    let platformHandle: String
    let platformId: String?
    let linkType: String

    enum CodingKeys: String, CodingKey {
        case platform
        case platformHandle = "platform_handle"
        case platformId = "platform_id"
        case linkType = "link_type"
    }
}

/// Private Codable evidence matching Rust `AttestationEvidence` JSON.
private struct AttestationEvidenceWire: Codable {
    let method: String
    let proof: String
    let verifiedAt: UInt64
    let verifierDid: String?

    enum CodingKeys: String, CodingKey {
        case method
        case proof
        case verifiedAt = "verified_at"
        case verifierDid = "verifier_did"
    }
}

/// Private Codable type matching the Rust `IdentityLinkAttestation` JSON
/// wire format produced by `serde_json::to_string`. Used to translate
/// between the UniFFI bridge's JSON strings and the public
/// ``IdentityAttestation`` value type.
///
/// Properties use camelCase; `CodingKeys` map to Rust's snake_case JSON.
private struct AttestationWire: Codable {
    let id: String
    let typeField: String
    let issuer: String
    let subject: String
    let issuedAt: UInt64
    let expiresAt: UInt64?
    let claim: AttestationClaimWire
    let evidence: AttestationEvidenceWire
    let revocationStatus: String
    let signature: [UInt8]?

    enum CodingKeys: String, CodingKey {
        case id
        case typeField = "type"
        case issuer
        case subject
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case claim
        case evidence
        case revocationStatus = "revocation_status"
        case signature
    }

    /// Parses a single attestation from the bridge JSON string.
    static func parseAttestation(from json: String) throws -> IdentityAttestation {
        guard let data = json.data(using: .utf8) else {
            throw ScpError.Identity(
                msg: "attestation JSON is not valid UTF-8",
                code: "SCP-ATTEST-9015"
            )
        }
        let decoder = JSONDecoder()
        let wire = try decoder.decode(AttestationWire.self, from: data)
        return wire.toIdentityAttestation(rawJson: json)
    }

    /// Parses a JSON array of attestations from the bridge.
    static func parseAttestations(from json: String) throws -> [IdentityAttestation] {
        guard let data = json.data(using: .utf8) else {
            throw ScpError.Identity(
                msg: "attestation list JSON is not valid UTF-8",
                code: "SCP-ATTEST-9016"
            )
        }
        let decoder = JSONDecoder()
        let wires = try decoder.decode([AttestationWire].self, from: data)
        // Re-serialize each element individually to preserve per-attestation
        // rawJson for roundtrip signature verification.
        let encoder = JSONEncoder()
        return try wires.map { wire in
            let elementJson = try String(data: encoder.encode(wire), encoding: .utf8)
            return wire.toIdentityAttestation(rawJson: elementJson)
        }
    }

    /// Re-serializes an ``IdentityAttestation`` into the bridge JSON format.
    ///
    /// Used by the verify bridge when ``IdentityAttestation/rawJson`` is `nil`.
    static func serializeAttestation(_ attestation: IdentityAttestation) throws -> String {
        let wire = AttestationWire(
            id: attestation.id,
            typeField: "identity_link",
            issuer: "", // Verification uses the issuer DID from the full wire format
            subject: "",
            issuedAt: attestation.verifiedAt,
            expiresAt: nil,
            claim: AttestationClaimWire(
                platform: attestation.platform,
                platformHandle: attestation.platformHandle,
                platformId: attestation.platformId,
                linkType: "self_attestation"
            ),
            evidence: AttestationEvidenceWire(
                method: attestation.verificationMethod,
                proof: "",
                verifiedAt: attestation.verifiedAt,
                verifierDid: nil
            ),
            revocationStatus: attestation.revocationStatus == .active ? "Active" : "Revoked",
            signature: nil
        )
        let encoder = JSONEncoder()
        guard let json = try String(data: encoder.encode(wire), encoding: .utf8) else {
            throw ScpError.Identity(
                msg: "failed to encode attestation as UTF-8 JSON",
                code: "SCP-ATTEST-9017"
            )
        }
        return json
    }

    /// Converts the wire format to the public ``IdentityAttestation`` type.
    func toIdentityAttestation(rawJson: String?) -> IdentityAttestation {
        let status: RevocationStatus = revocationStatus == "Active"
            ? .active
            : .revoked(revokedAt: issuedAt, reason: nil)
        return IdentityAttestation(
            id: id,
            platform: claim.platform,
            platformHandle: claim.platformHandle,
            verificationMethod: evidence.method,
            verifiedAt: evidence.verifiedAt,
            revocationStatus: status,
            platformId: claim.platformId,
            rawJson: rawJson
        )
    }
}

// MARK: - Identity Attestation Public API

/// Creates an identity link attestation for an external platform (§3.5).
///
/// - Parameters:
///   - did: The DID claiming the external identity.
///   - platform: Platform identifier (e.g., `"github.com"`).
///   - handle: Platform-specific handle or username.
///   - proof: Platform-specific proof of ownership.
///   - verificationMethod: One of `"oauth"`, `"signed_post"`, `"dns_record"`,
///     `"challenge_response"`. Defaults to `"oauth"`.
///   - platformId: Optional platform-assigned unique identifier.
///   - createFn: Bridge function override for testing.
/// - Returns: The created ``IdentityAttestation``.
/// - Throws: ``ScpError/Identity(msg:code:)`` if creation fails.
///
/// ## Provenance
///
/// - Spec section 3.5 (Identity Link Attestations)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func createIdentityAttestation(
    did: String,
    platform: String,
    handle: String,
    proof: String,
    verificationMethod: String = "oauth",
    platformId: String? = nil,
    createFn: IdentityAttestationBridge.CreateFn = IdentityAttestationBridge.defaultCreate
) async throws -> IdentityAttestation {
    try await createFn(did, platform, handle, proof, verificationMethod, platformId)
}

/// Lists all identity link attestations for an identity.
///
/// - Parameters:
///   - did: The DID to list attestations for.
///   - listFn: Bridge function override for testing.
/// - Returns: An array of ``IdentityAttestation`` objects.
/// - Throws: ``ScpError/Identity(msg:code:)`` if listing fails.
///
/// ## Provenance
///
/// - Spec section 3.5 (Identity Link Attestations)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func listIdentityAttestations(
    did: String,
    listFn: IdentityAttestationBridge.ListFn = IdentityAttestationBridge.defaultList
) async throws -> [IdentityAttestation] {
    try await listFn(did)
}

/// Removes an identity link attestation by ID.
///
/// - Parameters:
///   - did: The DID that owns the attestation.
///   - attestationId: The deterministic attestation ID to remove.
///   - removeFn: Bridge function override for testing.
/// - Returns: `true` if the attestation was found and removed.
/// - Throws: ``ScpError/Identity(msg:code:)`` if removal fails.
///
/// ## Provenance
///
/// - Spec section 3.5 (Identity Link Attestations)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func removeIdentityAttestation(
    did: String,
    attestationId: String,
    removeFn: IdentityAttestationBridge.RemoveFn = IdentityAttestationBridge.defaultRemove
) async throws -> Bool {
    try await removeFn(did, attestationId)
}
