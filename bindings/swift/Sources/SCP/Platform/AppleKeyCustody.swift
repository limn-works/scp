import CommonCrypto
import CryptoKit
import Foundation
import Security

// MARK: - PlatformError

/// Errors thrown by the Apple platform key custody adapter.
///
/// Maps to the Rust `PlatformError` enum in `scp-platform/src/error.rs`.
/// All variants carry descriptive messages suitable for logging. Private key
/// material is never included in error messages.
///
/// See ADR-025 for the full Apple platform adapter design and ADR-006 for the
/// `KeyCustody` trait specification.
public nonisolated enum PlatformError: Error, Sendable {
    /// A Keychain operation failed. The associated `OSStatus` is the raw
    /// Security framework status code (e.g. `errSecDuplicateItem = -25299`).
    case keychainError(OSStatus)
    /// The key handle is not present in the Keychain. Either the handle is
    /// invalid or the key was previously destroyed.
    case keyNotFound(String)
    /// A cryptographic operation was attempted with a key of the wrong type.
    /// For example, calling `sign` with an X25519 handle or `dhAgree` with
    /// an Ed25519 handle.
    case wrongKeyType(String)
    /// Key destruction was initiated but the Keychain item persisted after
    /// deletion. The associated string is the key handle that could not be
    /// confirmed as destroyed.
    case destructionFailed(String)
    /// Biometric authentication failed or was cancelled by the user. The
    /// Keychain refused to release key material because the biometric check
    /// did not succeed.
    case biometricAuthenticationFailed(String)
    /// A general custody operation failed for reasons other than the variants
    /// above.
    case custodyError(String)
}

nonisolated extension PlatformError: LocalizedError {
    /// Human-readable error description. Safe for logging; no key material.
    public nonisolated var errorDescription: String? {
        switch self {
        case let .keychainError(status):
            "Keychain operation failed with OSStatus \(status)"
        case let .keyNotFound(handle):
            "Key not found for handle '\(handle)'"
        case let .wrongKeyType(detail):
            "Wrong key type: \(detail)"
        case let .destructionFailed(handle):
            "Key destruction failed: item persisted for handle '\(handle)'"
        case let .biometricAuthenticationFailed(detail):
            "Biometric authentication failed: \(detail)"
        case let .custodyError(message):
            "Key custody error: \(message)"
        }
    }
}

// MARK: - KeyType

/// The cryptographic key type managed by ``AppleKeyCustody``.
///
/// Keys are tagged with their type at creation time so that subsequent
/// operations can enforce type safety (e.g. ``AppleKeyCustody/sign(_:data:)``
/// only accepts ``ed25519`` handles).
///
/// See ADR-006 for the `KeyType` enum specification and ADR-025 for the Apple
/// platform adapter design.
public nonisolated enum KeyType: String, Sendable, Equatable {
    /// Ed25519 signing key. Used for identity keys and active signing keys.
    /// Private bytes are 32 bytes; public bytes are 32 bytes.
    case ed25519
    /// X25519 key-agreement key. Used for HPKE wrapping keys. Private bytes
    /// are 32 bytes; public bytes are 32 bytes.
    case x25519
}

// MARK: - BiometricPolicy

/// Controls whether biometric authentication (Face ID / Touch ID) is
/// required before the Keychain releases key material for signing and
/// key-agreement operations.
///
/// See ADR-025 Biometric gating for the design rationale and industry
/// comparison (Signal, WhatsApp).
public nonisolated enum BiometricPolicy: String, Sendable, Equatable {
    /// No biometric gate. Keys use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
    /// -- the default behavior. Background operations (relay connections, message
    /// processing) can access keys while the device is locked after first unlock.
    case none

    /// Biometric authentication (Face ID / Touch ID) is required every time
    /// `sign`, `dhAgree`, or `derivePseudonym` accesses key material. The
    /// Keychain item is created with `SecAccessControl` using
    /// `.biometryCurrentSet`, which ties access to the currently enrolled
    /// biometrics. If biometrics change (e.g., a new fingerprint is enrolled),
    /// existing keys become inaccessible -- triggering key rotation per 9.12.
    ///
    /// If the device has no biometric hardware, the system falls back to
    /// device passcode authentication.
    case required
}

// MARK: - DestructionAttestation

/// Attestation that a key has been destroyed.
///
/// Returned by ``AppleKeyCustody/destroyKey(_:)`` after successful deletion
/// and re-fetch confirmation. For Apple Keychain-backed keys, `method` is
/// always `.softwareOnly` because the key material lives in software (Keychain)
/// rather than a hardware security module.
///
/// See 9.15 of the SCP specification for key destruction requirements and
/// ADR-025 for the rationale behind software-only attestation on Apple platforms.
public nonisolated struct DestructionAttestation: Sendable {
    /// The destruction method. `.softwareOnly` for Keychain keys.
    public nonisolated let method: DestructionMethod
    /// `true` when the re-fetch after deletion confirmed `errSecItemNotFound`.
    public nonisolated let confirmed: Bool

    /// Memberwise initializer.
    public nonisolated init(method: DestructionMethod, confirmed: Bool) {
        self.method = method
        self.confirmed = confirmed
    }
}

/// The mechanism by which key material was destroyed.
///
/// See 9.15 of the SCP specification.
public nonisolated enum DestructionMethod: String, Sendable {
    /// Key material was deleted from software storage (e.g., Apple Keychain).
    /// No hardware destruction guarantee is available.
    case softwareOnly
    /// Key material was destroyed by the hardware security module. Not
    /// applicable to Apple Keychain-backed keys.
    case hardware
}

// MARK: - KeyMetadata

/// Internal metadata stored alongside a Keychain key item.
///
/// Encoded as a compact JSON blob and stored in `kSecAttrLabel`. This allows
/// type-checking, role reporting and public key retrieval without accessing
/// key material (which would trigger biometric prompts on gated keys).
private nonisolated struct KeyMetadata: Codable {
    /// The ``KeyType`` of the stored key.
    let keyType: String
    /// Base64-encoded 32-byte public key bytes, stored at generation time.
    /// `nil` for legacy items created before metadata caching was added.
    let publicKeyBase64: String?
    /// The ``KeyRole`` raw value the key was minted in. Required: an item
    /// without it fails to decode, so a role is never guessed.
    let role: String
}

/// The role a key was minted in, stored in ``KeyMetadata`` and reported as
/// the UniFFI `CustodyKeyRole` from `getPublicKey(keyId:)`.
private nonisolated enum KeyRole: String {
    case identity
    case operational

    init(_ role: CustodyKeyRole) {
        switch role {
        case .identity: self = .identity
        case .operational: self = .operational
        }
    }

    var custodyKeyRole: CustodyKeyRole {
        switch self {
        case .identity: .identity
        case .operational: .operational
        }
    }
}

// MARK: - AppleKeyCustody

/// Apple Keychain-backed key custody provider for SCP Ed25519 and X25519 keys.
///
/// The class conforms to the UniFFI `KeyCustodyProvider` callback interface
/// (`crates/scp-ffi/uniffi/src/lib.rs`), as ADR-025 requires, so an instance
/// passes directly to `identityCreateWithCustody(provider:)` and every other
/// bridge call that takes a provider. The `os_keystore` custody of spec 03
/// §3.2.2 reaches the Keychain through it with no caller glue.
///
/// ## Key ids
///
/// A key id is the canonical decimal form of a random `UInt64`, as
/// `String(n)` writes it, which is the only id shape the bridge accepts.
/// Generation adds the Keychain item without replacing an existing one and
/// draws a fresh id on `errSecDuplicateItem`, so a live key never shares an
/// id. An id that names a destroyed key is drawn again with probability
/// 2^-64 per earlier key.
///
/// ## Key storage
///
/// Each key is stored as a `kSecClassGenericPassword` Keychain item:
/// - `kSecAttrAccount`: `"scp.key.<id>"` where `<id>` is the key id.
/// - `kSecAttrLabel`: JSON-encoded ``KeyMetadata`` (type, role and cached
///   public key).
/// - `kSecAttrAccessGroup`: `"\(appIdentifierPrefix).dev.limn.scp"`.
/// - `kSecAttrAccessible`: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
/// - `kSecValueData`: 32-byte raw private key bytes.
///
/// ## Biometric gating
///
/// When initialized with ``BiometricPolicy/required``, key material is stored
/// with `SecAccessControl` requiring `.biometryCurrentSet` -- Face ID or Touch
/// ID must authenticate before `sign`, `dhAgree`, or `derivePseudonym` can
/// access the Keychain item. `publicKey` and `destroyKey` do NOT require
/// biometric authentication -- `publicKey` reads from metadata cache (attributes
/// only, no key material access), and `destroyKey` is a cleanup operation.
/// If the device has no biometric hardware, the system falls back to device
/// passcode. See ADR-025 Biometric gating.
///
/// ## Secure Enclave note
///
/// Apple's Secure Enclave only supports P-256 (NIST P-256 / secp256r1) key
/// operations. SCP uses Ed25519 for signing and X25519 for key agreement;
/// neither is supported by the Secure Enclave. All SCP identity keys on
/// Apple platforms are therefore software-backed via Keychain. The Secure
/// Enclave is used exclusively by `AppleDeviceAttestation` for App Attest
/// attestation (which uses a P-256 key internally). See ADR-025 Rationale.
///
/// ## Thread safety
///
/// All Keychain operations are synchronous at the `Security.framework` level.
/// This class wraps them in `async` methods so callers can `await` them without
/// blocking a thread. Each operation creates and disposes its own Keychain
/// query dictionary; there is no shared mutable state beyond the Keychain itself.
///
/// ## Concurrency isolation
///
/// `AppleKeyCustody` runs its async operations `@concurrent` (off the main
/// actor) because Keychain I/O must not block the main thread. With Swift 6.2
/// approachable concurrency (`SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`),
/// using `@concurrent` is the correct way to force background execution.
///
/// See ADR-025 for the full design rationale and 9.15 for key destruction
/// requirements.
public final class AppleKeyCustody: Sendable {
    // MARK: - Configuration

    /// The Keychain access group for all SCP key items.
    ///
    /// The `$(AppIdentifierPrefix)` component (team ID prefix) is expanded at
    /// runtime from the app's provisioning profile. When running in unit-test
    /// or simulator contexts without a provisioning profile, pass an empty
    /// string or omit the access group to use the default keychain.
    private let accessGroup: String?

    /// The biometric authentication policy for key access operations.
    ///
    /// When `.required`, signing, key agreement, and pseudonym derivation
    /// operations require Face ID / Touch ID before the Keychain releases
    /// key material. When `.none`, keys use standard
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` protection with
    /// no biometric gate.
    ///
    /// See ADR-025 Biometric gating.
    let biometricPolicy: BiometricPolicy

    // MARK: - Keychain item attribute helpers

    /// Returns the `kSecAttrAccount` value for a key handle.
    private nonisolated func account(for handle: String) -> String {
        "scp.key.\(handle)"
    }

    // MARK: - Initialization

    /// Creates a new `AppleKeyCustody` instance.
    ///
    /// - Parameters:
    ///   - accessGroup: The Keychain access group to use for all key
    ///     items. Pass `nil` to use the default Keychain (suitable for unit
    ///     tests and simulator). In production, pass
    ///     `"\(teamId).dev.limn.scp"` where `teamId` is the app's Apple Team ID
    ///     prefix (the `$(AppIdentifierPrefix)` build setting).
    ///   - biometricPolicy: Controls whether biometric authentication is
    ///     required before key access. Defaults to `.none` (no biometric gate),
    ///     preserving the existing behavior. Pass `.required` to gate signing,
    ///     key agreement, and pseudonym derivation behind Face ID / Touch ID.
    ///
    /// See ADR-025 for the access group rationale and Biometric gating for
    /// the biometric policy design.
    public init(accessGroup: String? = nil, biometricPolicy: BiometricPolicy = .none) {
        self.accessGroup = accessGroup
        self.biometricPolicy = biometricPolicy
    }

    // MARK: - Private Keychain helpers

    /// `kSecAttrDescription` tag recording the biometric policy an item was
    /// stored under, so a re-store can tell whether the existing item's
    /// access control matches the current policy.
    private nonisolated var policyTag: String {
        "scp.policy.\(biometricPolicy.rawValue)"
    }

    /// Builds a base Keychain query dictionary for a key handle.
    ///
    /// All operations (add, fetch, delete) start from this base and extend it
    /// with operation-specific keys.
    private nonisolated func baseQuery(for handle: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account(for: handle)
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        return query
    }

    /// Reads the full ``KeyMetadata`` for `handle` from Keychain attributes.
    ///
    /// Reads `kSecReturnAttributes` only (NOT `kSecReturnData`), so this
    /// does NOT trigger biometric prompts on gated keys.
    private nonisolated func fetchMetadata(for handle: String) throws -> KeyMetadata {
        var query = baseQuery(for: handle)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard
                let attrs = result as? [String: Any],
                let labelString = attrs[kSecAttrLabel as String] as? String,
                let labelData = labelString.data(using: .utf8),
                let metadata = try? JSONDecoder().decode(KeyMetadata.self, from: labelData)
            else {
                throw PlatformError.custodyError(
                    "Could not decode key metadata for handle '\(handle)'"
                )
            }
            return metadata
        case errSecItemNotFound:
            throw PlatformError.keyNotFound(handle)
        default:
            throw PlatformError.keychainError(status)
        }
    }

    /// Reads the raw 32-byte private key bytes for `handle` from the Keychain.
    ///
    /// - Parameter handle: The key id returned by
    ///   ``generateKeypair(keyType:)``.
    /// - Returns: The raw private key bytes.
    /// - Throws: ``PlatformError/keyNotFound(_:)`` if the item does not exist,
    ///   ``PlatformError/biometricAuthenticationFailed(_:)`` if the user
    ///   cancelled the biometric prompt or authentication failed,
    ///   or ``PlatformError/keychainError(_:)`` for other Keychain failures.
    private nonisolated func fetchPrivateKeyBytes(for handle: String) throws -> Data {
        var query = baseQuery(for: handle)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw PlatformError.custodyError(
                    "Keychain returned unexpected data type for handle '\(handle)'"
                )
            }
            return data
        case errSecItemNotFound:
            throw PlatformError.keyNotFound(handle)
        case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
            throw PlatformError.biometricAuthenticationFailed(
                "Biometric authentication failed for handle '\(handle)' (OSStatus \(status))"
            )
        default:
            throw PlatformError.keychainError(status)
        }
    }

    /// Reads the ``KeyType``-tagged metadata label for `handle`.
    ///
    /// Delegates to ``fetchMetadata(for:)`` and extracts the key type.
    /// Does NOT trigger biometric prompts (reads attributes only).
    private nonisolated func fetchKeyType(for handle: String) throws -> KeyType {
        let metadata = try fetchMetadata(for: handle)
        guard let keyType = KeyType(rawValue: metadata.keyType) else {
            throw PlatformError.custodyError(
                "Unknown key type '\(metadata.keyType)' for handle '\(handle)'"
            )
        }
        return keyType
    }

    /// Reads the role `handle` was minted in from its metadata label.
    /// Does NOT trigger biometric prompts (reads attributes only).
    private nonisolated func fetchRole(for handle: String) throws -> KeyRole {
        let metadata = try fetchMetadata(for: handle)
        guard let role = KeyRole(rawValue: metadata.role) else {
            throw PlatformError.custodyError(
                "Unknown key role '\(metadata.role)' for handle '\(handle)'"
            )
        }
        return role
    }

    /// A `SecAccessControl` requiring the currently enrolled biometric set.
    /// `.biometryCurrentSet` invalidates access if biometrics change (new
    /// fingerprint enrolled, Face ID reset), which triggers key rotation per
    /// 9.12. Falls back to device passcode on hardware without biometric
    /// sensors.
    private nonisolated func biometricAccessControl(for handle: String) throws -> SecAccessControl {
        var cfError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &cfError
        ) else {
            let errorDesc = cfError.map { ($0.takeRetainedValue() as Error).localizedDescription }
                ?? "unknown error"
            throw PlatformError.custodyError(
                "Failed to create biometric access control for handle '\(handle)': \(errorDesc)"
            )
        }
        return accessControl
    }

    /// Stores 32-byte raw private key bytes in the Keychain under `handle`.
    ///
    /// The public key bytes are cached in the ``KeyMetadata`` label so that
    /// ``publicKey(_:)`` can return them without accessing key material
    /// (avoiding biometric prompts on gated keys).
    ///
    /// When ``biometricPolicy`` is `.required`, the item is stored with
    /// `SecAccessControl` requiring `.biometryCurrentSet`. When `.none`,
    /// the item uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
    ///
    /// An existing item under `handle` is replaced. Key generation does not
    /// use this method: it must never overwrite a key, so it adds through
    /// ``mintKey(keyType:role:)``.
    ///
    /// - Parameters:
    ///   - bytes: The raw 32-byte private key bytes.
    ///   - handle: The key id that will reference this key.
    ///   - keyType: The ``KeyType`` to tag this item with.
    ///   - role: The role to record for the key's lifetime.
    ///   - publicKeyBytes: The public key bytes to cache in metadata.
    /// - Throws: ``PlatformError/keychainError(_:)`` if the add operation fails.
    nonisolated func storePrivateKeyBytes(
        _ bytes: Data,
        for handle: String,
        keyType: KeyType,
        role: CustodyKeyRole,
        publicKeyBytes: Data
    ) throws {
        let query = try addQuery(
            bytes, for: handle, keyType: keyType, role: role, publicKeyBytes: publicKeyBytes
        )
        let status = SecItemAdd(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            break
        case errSecDuplicateItem:
            try replaceExisting(handle: handle, query: query)
        default:
            throw PlatformError.keychainError(status)
        }
    }

    /// Builds the `SecItemAdd` query that stores `bytes` under `handle` with
    /// its metadata label and the access control of ``biometricPolicy``.
    private nonisolated func addQuery(
        _ bytes: Data,
        for handle: String,
        keyType: KeyType,
        role: CustodyKeyRole,
        publicKeyBytes: Data
    ) throws -> [String: Any] {
        let metadata = KeyMetadata(
            keyType: keyType.rawValue,
            publicKeyBase64: publicKeyBytes.base64EncodedString(),
            role: KeyRole(role).rawValue
        )
        guard
            let metadataData = try? JSONEncoder().encode(metadata),
            let metadataLabel = String(data: metadataData, encoding: .utf8)
        else {
            throw PlatformError.custodyError(
                "Failed to encode key metadata for handle '\(handle)'"
            )
        }

        var query = baseQuery(for: handle)
        query[kSecAttrLabel as String] = metadataLabel
        query[kSecValueData as String] = bytes as CFData
        query[kSecAttrDescription as String] = policyTag

        switch biometricPolicy {
        case .none:
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        case .required:
            query[kSecAttrAccessControl as String] = try biometricAccessControl(for: handle)
        }
        return query
    }

    /// The number of fresh ids ``mintKey(keyType:role:)`` draws before it
    /// gives up. Eight collisions in a row among random 64-bit ids means the
    /// Keychain is not behaving as a store, not bad luck.
    private nonisolated static let mintAttempts = 8

    /// Generates a `keyType` keypair minted in `role`, adds it under a fresh
    /// random decimal `UInt64` id, and returns that id.
    ///
    /// The add never replaces an item: `errSecDuplicateItem` draws another
    /// id, so a live key is never overwritten and never shares its id.
    ///
    /// - Throws: ``PlatformError/keychainError(_:)`` if the add fails,
    ///   ``PlatformError/custodyError(_:)`` if every drawn id is taken.
    nonisolated func mintKey(keyType: KeyType, role: CustodyKeyRole) throws -> String {
        var privateKeyBytes: Data
        let publicKeyBytes: Data
        switch keyType {
        case .ed25519:
            let signingKey = Curve25519.Signing.PrivateKey()
            privateKeyBytes = signingKey.rawRepresentation
            publicKeyBytes = signingKey.publicKey.rawRepresentation
        case .x25519:
            let agreementKey = Curve25519.KeyAgreement.PrivateKey()
            privateKeyBytes = agreementKey.rawRepresentation
            publicKeyBytes = agreementKey.publicKey.rawRepresentation
        }
        defer { privateKeyBytes.resetBytes(in: 0 ..< privateKeyBytes.count) }

        for _ in 0 ..< Self.mintAttempts {
            let handle = String(UInt64.random(in: .min ... .max))
            let query = try addQuery(
                privateKeyBytes, for: handle, keyType: keyType, role: role, publicKeyBytes: publicKeyBytes
            )
            let status = SecItemAdd(query as CFDictionary, nil)
            switch status {
            case errSecSuccess:
                return handle
            case errSecDuplicateItem:
                continue
            default:
                throw PlatformError.keychainError(status)
            }
        }
        throw PlatformError.custodyError(
            "No free key id after \(Self.mintAttempts) draws"
        )
    }

    /// Resolves an `errSecDuplicateItem` from storing `query` under `handle`:
    /// the existing item is replaced, so the new bytes and the current
    /// biometric policy apply.
    private nonisolated func replaceExisting(
        handle: String,
        query: [String: Any]
    ) throws {
        let deleteStatus = SecItemDelete(baseQuery(for: handle) as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw PlatformError.keychainError(deleteStatus)
        }
        let retryStatus = SecItemAdd(query as CFDictionary, nil)
        guard retryStatus == errSecSuccess else {
            throw PlatformError.keychainError(retryStatus)
        }
    }
}

// MARK: - Ed25519 to X25519

extension AppleKeyCustody {
    /// The X25519 scalar of an Ed25519 key: the first 32 bytes of
    /// `SHA-512(seed)`, unclamped (X25519 clamps when it multiplies). The
    /// 64-byte hash buffer is wiped before return.
    nonisolated static func x25519Scalar(fromEd25519Seed seed: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        defer { digest.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        seed.withUnsafeBytes { buffer in
            _ = CC_SHA512(buffer.baseAddress, CC_LONG(buffer.count), &digest)
        }
        return Data(digest[0 ..< 32])
    }
}

// MARK: - Pseudonym derivation

extension AppleKeyCustody {
    /// Shared §9.10.4.A derivation: reads the Ed25519 seed of
    /// `identityHandle` and returns the 33-byte compressed pseudonym point
    /// computed by the shared Rust helper. `epoch` is `nil` for the v1
    /// (static) pseudonym. Nothing is stored: a pseudonym has no private key
    /// after this call, so destroying the identity leaves nothing to derive
    /// from.
    nonisolated func derivePseudonymPoint(
        method: String,
        identityHandle: String,
        contextId: Data,
        epoch: UInt64?
    ) throws -> Data {
        let storedType = try fetchKeyType(for: identityHandle)
        guard storedType == .ed25519 else {
            throw PlatformError.wrongKeyType(
                "\(method) requires an Ed25519 key; handle '\(identityHandle)' is \(storedType.rawValue)"
            )
        }

        var identitySeed = try fetchPrivateKeyBytes(for: identityHandle)
        defer { identitySeed.resetBytes(in: 0 ..< identitySeed.count) }

        do {
            return try p256SoftwarePseudonymPoint(ikm: identitySeed, contextId: contextId, epoch: epoch)
        } catch let scpErr as ScpError {
            // The shared helper's typed error and code reach the caller
            // unchanged, as in the Kotlin SDK.
            throw scpErr
        } catch {
            throw PlatformError.custodyError(
                "P-256 pseudonym derivation failed: \(error.localizedDescription)"
            )
        }
    }
}

// MARK: - Key custody operations

public extension AppleKeyCustody {
    // MARK: generateKeypair

    /// Generates an Ed25519 or X25519 keypair and stores the private key in
    /// the Apple Keychain.
    ///
    /// The private key bytes are stored as a `kSecClassGenericPassword` item.
    /// When ``biometricPolicy`` is `.none`, the item uses
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, ensuring background
    /// operations can access keys while the device is locked. When `.required`,
    /// the item uses `SecAccessControl` with `.biometryCurrentSet`. The key
    /// never leaves the Keychain after generation; all operations retrieve
    /// it on demand and operate in-process.
    ///
    /// The key is minted in the operational role. An identity key comes from
    /// the bridge through `generateKeypair(keyType:role:)`, which records the
    /// role the bridge names.
    ///
    /// - Parameter keyType: `"ed25519"` or `"x25519"`.
    /// - Returns: The key id, a canonical decimal `UInt64` string. Pass this
    ///   to other methods on this instance to perform operations with the key.
    /// - Throws: ``PlatformError/keychainError(_:)`` if the Keychain add fails,
    ///   ``PlatformError/custodyError(_:)`` for an unknown `keyType` string.
    ///
    /// See ADR-025 Key custody and ADR-006 `generate_keypair`.
    @concurrent
    func generateKeypair(keyType: String) async throws -> String {
        guard let parsedType = KeyType(rawValue: keyType) else {
            throw PlatformError.custodyError("Unknown key type '\(keyType)'")
        }
        return try mintKey(keyType: parsedType, role: .operational)
    }

    // MARK: sign

    /// Signs `data` with the Ed25519 key identified by `keyHandle` and
    /// returns the 64-byte Ed25519 signature.
    ///
    /// The private key bytes are held in memory only for the duration of this
    /// call. They are not cached, logged, or returned across the FFI boundary.
    ///
    /// - Parameters:
    ///   - keyHandle: The key id returned by ``generateKeypair(keyType:)``
    ///     for an `"ed25519"` key.
    ///   - data: The bytes to sign.
    /// - Returns: A 64-byte signature.
    /// - Throws: ``PlatformError/wrongKeyType(_:)`` if `keyHandle` refers to
    ///   an X25519 key, ``PlatformError/keyNotFound(_:)`` if the handle is
    ///   unknown, ``PlatformError/biometricAuthenticationFailed(_:)`` if
    ///   biometric gating is active and authentication fails,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` if CryptoKit rejects Ed25519 key
    ///   bytes.
    ///
    /// See ADR-025 Key custody and ADR-006 `sign`.
    @concurrent
    func sign(_ keyHandle: String, data: Data) async throws -> Data {
        let storedType = try fetchKeyType(for: keyHandle)
        guard storedType != .x25519 else {
            throw PlatformError.wrongKeyType(
                "sign requires an Ed25519 key; handle '\(keyHandle)' is X25519"
            )
        }

        var privateKeyBytes = try fetchPrivateKeyBytes(for: keyHandle)
        defer { privateKeyBytes.resetBytes(in: 0 ..< privateKeyBytes.count) }

        do {
            let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
            return try signingKey.signature(for: data)
        } catch let platformErr as PlatformError {
            throw platformErr
        } catch {
            throw PlatformError.custodyError(
                "Ed25519 signing failed for handle '\(keyHandle)': \(error.localizedDescription)"
            )
        }
    }

    // MARK: publicKey

    /// Returns the 32-byte public key for any key handle.
    ///
    /// Reads the cached public key from Keychain metadata attributes. This
    /// does NOT access key material and therefore does NOT trigger biometric
    /// prompts on gated keys. Falls back to private-key derivation for legacy
    /// items that predate the metadata cache.
    ///
    /// - Parameter keyHandle: The key id returned by
    ///   ``generateKeypair(keyType:)``.
    /// - Returns: The raw public key bytes.
    /// - Throws: ``PlatformError/keyNotFound(_:)`` if the handle is unknown,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` if the stored key type is unknown
    ///   or CryptoKit rejects Ed25519 or X25519 key bytes.
    ///
    /// See ADR-025 Key custody and ADR-006 `public_key`.
    @concurrent
    func publicKey(_ keyHandle: String) async throws -> Data {
        let metadata = try fetchMetadata(for: keyHandle)
        guard let keyType = KeyType(rawValue: metadata.keyType) else {
            throw PlatformError.custodyError(
                "Unknown key type '\(metadata.keyType)' for handle '\(keyHandle)'"
            )
        }

        // Read from metadata cache (attributes only -- no biometric prompt).
        if let pubKeyBase64 = metadata.publicKeyBase64,
           let pubKeyData = Data(base64Encoded: pubKeyBase64),
           pubKeyData.count == 32 {
            return pubKeyData
        }

        // Fallback for legacy keys stored before metadata caching: derive
        // from private key. This WILL trigger biometric prompt if active.
        var privateKeyBytes = try fetchPrivateKeyBytes(for: keyHandle)
        defer { privateKeyBytes.resetBytes(in: 0 ..< privateKeyBytes.count) }

        do {
            switch keyType {
            case .ed25519:
                let signingKey = try Curve25519.Signing.PrivateKey(
                    rawRepresentation: privateKeyBytes
                )
                return signingKey.publicKey.rawRepresentation
            case .x25519:
                let agreementKey = try Curve25519.KeyAgreement.PrivateKey(
                    rawRepresentation: privateKeyBytes
                )
                return agreementKey.publicKey.rawRepresentation
            }
        } catch let platformErr as PlatformError {
            throw platformErr
        } catch {
            throw PlatformError.custodyError(
                "Public key derivation failed for handle '\(keyHandle)': \(error.localizedDescription)"
            )
        }
    }

    // MARK: destroyKey

    /// Deletes the Keychain item for `keyHandle` and returns a destruction
    /// attestation after confirming that it no longer exists. No pseudonym
    /// item exists to delete: a pseudonym is a public point derived on
    /// demand from the identity seed, so once the seed is gone no pseudonym
    /// of this identity can be derived again (§9.10.4.A).
    ///
    /// ## Deletion verification
    ///
    /// After `SecItemDelete` succeeds, this method performs a re-fetch to
    /// confirm the item is no longer present. If the item still exists (i.e.,
    /// the re-fetch returns anything other than `errSecItemNotFound`), the
    /// method throws ``PlatformError/destructionFailed(_:)``.
    ///
    /// ## Attestation
    ///
    /// Returns a ``DestructionAttestation`` with `method: .softwareOnly` and
    /// `confirmed: true`. The `.softwareOnly` method reflects that Keychain
    /// keys have no hardware-level destruction guarantee -- contrast with App
    /// Attest P-256 keys managed by `DCAppAttestService`. See 9.15 of the
    /// SCP specification.
    ///
    /// - Parameter keyHandle: The key id returned by
    ///   ``generateKeypair(keyType:)``.
    /// - Returns: A ``DestructionAttestation`` confirming software deletion.
    /// - Throws: ``PlatformError/keyNotFound(_:)`` if the handle is already
    ///   absent, ``PlatformError/destructionFailed(_:)`` if the item persists
    ///   after deletion, ``PlatformError/keychainError(_:)`` for other
    ///   Keychain failures.
    ///
    /// See ADR-025 Key destruction attestation and 9.15.
    @concurrent
    @discardableResult
    func destroyKey(_ keyHandle: String) async throws -> DestructionAttestation {
        let deleteQuery = baseQuery(for: keyHandle)
        let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)

        switch deleteStatus {
        case errSecSuccess:
            break
        case errSecItemNotFound:
            throw PlatformError.keyNotFound(keyHandle)
        default:
            throw PlatformError.keychainError(deleteStatus)
        }

        // Confirm deletion by attempting a re-fetch.
        var verifyQuery = baseQuery(for: keyHandle)
        verifyQuery[kSecReturnData as String] = false
        verifyQuery[kSecMatchLimit as String] = kSecMatchLimitOne

        var verifyResult: AnyObject?
        let verifyStatus = SecItemCopyMatching(verifyQuery as CFDictionary, &verifyResult)

        guard verifyStatus == errSecItemNotFound else {
            // An item is still present -- destruction cannot be confirmed.
            throw PlatformError.destructionFailed(keyHandle)
        }

        return DestructionAttestation(method: .softwareOnly, confirmed: true)
    }

    // MARK: dhAgree

    /// Performs X25519 Diffie-Hellman key agreement.
    ///
    /// Retrieves the private key bytes from Keychain and computes the shared
    /// secret with `peerPublic`. For an X25519 key the stored bytes are the
    /// scalar. For an Ed25519 key the scalar is `SHA-512(seed)[0..32]`, the
    /// birational Ed25519-to-X25519 conversion the bridge's
    /// `ed25519_to_x25519_agree` asks for and Rust's
    /// `x25519_agree_from_ed25519` computes (`SigningKey::to_scalar_bytes`).
    /// The private key never crosses the `AppleKeyCustody` boundary -- the
    /// scalar multiplication happens entirely within this method, and every
    /// local copy of the seed, hash and scalar is wiped.
    ///
    /// - Parameters:
    ///   - keyHandle: The key id returned by ``generateKeypair(keyType:)``
    ///     for an `"x25519"` or `"ed25519"` key.
    ///   - peerPublic: The 32-byte X25519 public key of the peer.
    /// - Returns: 32-byte X25519 shared secret.
    /// - Throws: ``PlatformError/keyNotFound(_:)`` if the handle is
    ///   unknown, ``PlatformError/biometricAuthenticationFailed(_:)`` if
    ///   biometric gating is active and authentication fails,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` if the peer public key bytes are
    ///   invalid or CryptoKit rejects the key material.
    ///
    /// See ADR-025 Key custody and ADR-006 `dh_agree`.
    @concurrent
    func dhAgree(_ keyHandle: String, peerPublic: Data) async throws -> Data {
        let storedType = try fetchKeyType(for: keyHandle)

        var privateKeyBytes = try fetchPrivateKeyBytes(for: keyHandle)
        defer { privateKeyBytes.resetBytes(in: 0 ..< privateKeyBytes.count) }

        var scalar: Data
        switch storedType {
        case .x25519:
            scalar = Data(privateKeyBytes)
        case .ed25519:
            scalar = Self.x25519Scalar(fromEd25519Seed: privateKeyBytes)
        }
        defer { scalar.resetBytes(in: 0 ..< scalar.count) }

        do {
            let agreementKey = try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: scalar
            )
            let peerPublicKey = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: peerPublic
            )
            let sharedSecret = try agreementKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
            // Extract the raw 32 bytes from the SharedSecret. CryptoKit's
            // `SharedSecret` is opaque; `withUnsafeBytes` extracts the scalar.
            return sharedSecret.withUnsafeBytes { Data($0) }
        } catch let platformErr as PlatformError {
            throw platformErr
        } catch {
            throw PlatformError.custodyError(
                "X25519 DH agreement failed for handle '\(keyHandle)': \(error.localizedDescription)"
            )
        }
    }

    // MARK: derivePseudonym

    /// Derives the deterministic, context-scoped P-256 pseudonym of an
    /// Ed25519 identity key (spec §9.10.4.A) and returns its 33-byte
    /// compressed point.
    ///
    /// Reads the Ed25519 seed for `keyHandle` from Keychain (native software
    /// custody keys the recipe on this seed, §9.10.4 native interim), passes
    /// it to the shared Rust helper `p256SoftwarePseudonymPoint`, and wipes
    /// the local copy. The helper runs `pseudonym_secret = HKDF-SHA256(seed,
    /// "scp-pseudonym-secret-v1")`, `context_seed = HMAC-SHA256(
    /// pseudonym_secret, contextId || "scp-pseudonym")`, the FIPS 186-5
    /// A.2.1 reduction to a scalar, and returns the point. No pseudonym key
    /// is stored, and none can sign.
    ///
    /// **CRITICAL:** The HMAC key is derived from the private seed. Keying it
    /// on the public key would be a membership-enumeration oracle: anyone who
    /// knows a member's public key could compute their pseudonym for any
    /// context and check relay subscriptions.
    ///
    /// - Parameters:
    ///   - keyHandle: The handle of the **identity** Ed25519 key.
    ///   - contextId: The raw context ID bytes.
    /// - Returns: The 33-byte SEC1 compressed P-256 point.
    /// - Throws: ``PlatformError/wrongKeyType(_:)`` if `keyHandle` is not an
    ///   Ed25519 key, ``PlatformError/keyNotFound(_:)`` if the handle is
    ///   unknown (including after ``destroyKey(_:)``),
    ///   ``PlatformError/biometricAuthenticationFailed(_:)`` if biometric
    ///   gating is active and authentication fails,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures. The
    ///   shared Rust helper's error propagates unchanged:
    ///   ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7005` if the seed
    ///   is not 32 bytes. Any other error surfaces as
    ///   ``PlatformError/custodyError(_:)``.
    ///
    /// See spec §9.10.4.A and `derive_pseudonym` in
    /// `scp-crypto/src/pseudonym.rs` for the Rust reference.
    @concurrent
    func derivePseudonym(
        _ keyHandle: String,
        contextId: Data
    ) async throws -> Data {
        try derivePseudonymPoint(
            method: "derivePseudonym",
            identityHandle: keyHandle,
            contextId: contextId,
            epoch: nil
        )
    }

    // MARK: deriveRotatablePseudonym

    /// Derives the deterministic, context-scoped, epoch-rotatable P-256
    /// pseudonym of an Ed25519 identity key (rotation per spec §9.10.4.1,
    /// derivation per §9.10.4.A) and returns its 33-byte compressed point.
    ///
    /// Identical to ``derivePseudonym(_:contextId:)`` except that the
    /// context seed is `HMAC-SHA256(pseudonym_secret,
    /// contextId || BE64(pseudonymEpoch) || "scp-pseudonym-v2")`.
    ///
    /// - Parameters:
    ///   - keyHandle: The handle of the **identity** Ed25519 key.
    ///   - contextId: The raw context ID bytes.
    ///   - pseudonymEpoch: The rotation epoch.
    /// - Returns: The 33-byte SEC1 compressed P-256 point.
    /// - Throws: The same errors as ``derivePseudonym(_:contextId:)``.
    @concurrent
    func deriveRotatablePseudonym(
        _ keyHandle: String,
        contextId: Data,
        pseudonymEpoch: UInt64
    ) async throws -> Data {
        try derivePseudonymPoint(
            method: "deriveRotatablePseudonym",
            identityHandle: keyHandle,
            contextId: contextId,
            epoch: pseudonymEpoch
        )
    }

    // MARK: exportSigningKeyBytes

    /// Exports the raw 32-byte Ed25519 private key bytes for governance vote
    /// signing.
    ///
    /// Software-backed Keychain keys can export their private key bytes.
    /// Hardware-backed keys (e.g., Secure Enclave P-256 keys) cannot be
    /// exported, but SCP Ed25519 keys on Apple platforms are always
    /// Keychain-backed (software) because the Secure Enclave only supports
    /// P-256. See ADR-025 Rationale.
    ///
    /// - Parameter keyId: The key id returned by
    ///   ``generateKeypair(keyType:)``.
    /// - Returns: 32-byte raw Ed25519 private key bytes.
    /// - Throws: ``PlatformError/wrongKeyType(_:)`` if the key is X25519,
    ///   ``PlatformError/keyNotFound(_:)`` if the handle is unknown,
    ///   ``PlatformError/custodyError(_:)`` if the key type is
    ///   hardware-backed and non-extractable.
    @concurrent
    func exportSigningKeyBytes(_ keyId: String) async throws -> Data {
        let storedType = try fetchKeyType(for: keyId)
        guard storedType == .ed25519 else {
            throw PlatformError.wrongKeyType(
                "exportSigningKeyBytes requires an Ed25519 key; handle '\(keyId)' is \(storedType.rawValue)"
            )
        }

        var privateKeyBytes = try fetchPrivateKeyBytes(for: keyId)
        defer { privateKeyBytes.resetBytes(in: 0 ..< privateKeyBytes.count) }

        // Return a copy of the private key bytes (the defer zeroes the local copy).
        return Data(privateKeyBytes)
    }

    // MARK: custodyType

    /// Returns the custody type for any key handle managed by this instance.
    ///
    /// Returns `"software"` when no biometric policy is active, or
    /// `"software_biometric"` when biometric gating is enabled. Both are
    /// Keychain-backed (software) -- the Secure Enclave is NOT used for
    /// Ed25519/X25519 SCP keys (hardware supports P-256 only).
    ///
    /// See ADR-025 Rationale, Biometric gating, and 17.8 of the SCP
    /// specification.
    ///
    /// - Parameter keyHandle: The key id (not inspected; the custody type
    ///   is determined by the instance's ``biometricPolicy``).
    /// - Returns: `"software"` or `"software_biometric"` -- mirroring
    ///   `CustodyType::Software` in `scp-platform/src/traits.rs` with an
    ///   additional biometric qualifier when applicable.
    nonisolated func custodyType(_: String) -> String {
        switch biometricPolicy {
        case .none: "software"
        case .required: "software_biometric"
        }
    }
}

// MARK: - UniFFI KeyCustodyProvider conformance

/// `AppleKeyCustody` as the bridge's `KeyCustodyProvider` (ADR-025): each
/// witness forwards to the Swift-idiomatic method above and converts every
/// failure into the one error type UniFFI accepts from a callback, `ScpError`.
///
/// Error mapping follows the host contract on `KeyCustodyProvider` in
/// `crates/scp-ffi/uniffi/src/lib.rs`:
/// - an `ScpError` from the shared Rust helpers passes through unchanged;
/// - ``PlatformError/keyNotFound(_:)`` becomes `SCP-CRYPTO-4006`, which the
///   bridge reports as key-not-found;
/// - every other failure becomes `SCP-CRYPTO-4060`, the custody error,
///   carrying the adapter's description.
///
/// The adapter holds Ed25519 and X25519 keys. A P-256 or HPKE P-256 request
/// fails closed with `SCP-CRYPTO-4060`.
extension AppleKeyCustody: KeyCustodyProvider {
    /// Code the bridge reports as key-not-found.
    private nonisolated static let keyNotFoundCode = "SCP-CRYPTO-4006"
    /// Code the bridge reports as a custody failure.
    private nonisolated static let custodyErrorCode = "SCP-CRYPTO-4060"

    /// Converts any adapter failure into the `ScpError` the bridge accepts.
    private nonisolated static func providerError(_ error: Error) -> ScpError {
        switch error {
        case let scpError as ScpError:
            return scpError
        case let PlatformError.keyNotFound(handle):
            return .Crypto(msg: "Key not found for key id '\(handle)'", code: keyNotFoundCode)
        default:
            return .Crypto(msg: error.localizedDescription, code: custodyErrorCode)
        }
    }

    /// Runs `body` and rethrows its failure as an `ScpError`.
    private nonisolated static func bridged<T>(_ body: () async throws -> T) async throws -> T {
        do {
            return try await body()
        } catch {
            throw providerError(error)
        }
    }

    public func sign(keyId: String, message: Data) async throws -> Data {
        try await Self.bridged { try await sign(keyId, data: message) }
    }

    public func getPublicKey(keyId: String) async throws -> CustodyPublicKey {
        try await Self.bridged {
            let keyType: CustodyKeyType = switch try fetchKeyType(for: keyId) {
            case .ed25519: .ed25519
            case .x25519: .x25519
            }
            let role = try fetchRole(for: keyId).custodyKeyRole
            let publicKey = try await publicKey(keyId)
            return CustodyPublicKey(keyType: keyType, publicKey: publicKey, role: role)
        }
    }

    public func destroyKey(keyId: String) async throws {
        try await Self.bridged { _ = try await destroyKey(keyId) }
    }

    public func generateKeypair(keyType: CustodyKeyType, role: CustodyKeyRole) async throws -> String {
        try await Self.bridged {
            let adapterType: KeyType
            switch keyType {
            case .ed25519:
                adapterType = .ed25519
            case .x25519:
                adapterType = .x25519
            case .p256, .hpkeP256:
                // Stub — see SCP-307
                throw ScpError.Crypto(
                    msg: "AppleKeyCustody holds Ed25519 and X25519 keys only; \(keyType) is not supported",
                    code: Self.custodyErrorCode
                )
            }
            return try mintKey(keyType: adapterType, role: role)
        }
    }

    public func dhAgree(keyId: String, peerPublic: Data) async throws -> Data {
        try await Self.bridged { try await dhAgree(keyId, peerPublic: peerPublic) }
    }

    public func derivePseudonym(keyId: String, contextId: Data) async throws -> Data {
        try await Self.bridged { try await derivePseudonym(keyId, contextId: contextId) }
    }

    public func deriveRotatablePseudonym(
        keyId: String,
        contextId: Data,
        pseudonymEpoch: UInt64
    ) async throws -> Data {
        try await Self.bridged {
            try await deriveRotatablePseudonym(keyId, contextId: contextId, pseudonymEpoch: pseudonymEpoch)
        }
    }

    public func exportSigningKeyBytes(keyId: String) async throws -> Data {
        try await Self.bridged { try await exportSigningKeyBytes(keyId) }
    }

    public nonisolated func custodyType(keyId: String) -> String {
        custodyType(keyId)
    }
}
