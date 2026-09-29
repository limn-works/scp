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
    /// P-256 per-context pseudonym key (§9.10.4.A). Created only by
    /// ``AppleKeyCustody/derivePseudonym(_:contextId:)`` and its rotatable
    /// counterpart, never by ``AppleKeyCustody/generateKeypair(keyType:)``.
    /// The private scalar is 32 bytes; the public key is the 33-byte
    /// compressed point. It signs only a 32-byte digest.
    case p256Pseudonym = "p256"
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
/// type-checking and public key retrieval without accessing key material
/// (which would trigger biometric prompts on gated keys).
private nonisolated struct KeyMetadata: Codable {
    /// The ``KeyType`` of the stored key.
    let keyType: String
    /// Base64-encoded public key bytes, stored at generation time: 32 bytes,
    /// or the 33-byte compressed point for a P-256 pseudonym.
    /// `nil` for legacy items created before metadata caching was added.
    let publicKeyBase64: String?

    init(keyType: String, publicKeyBase64: String? = nil) {
        self.keyType = keyType
        self.publicKeyBase64 = publicKeyBase64
    }
}

// MARK: - AppleKeyCustody

/// Apple Keychain-backed key custody provider for SCP Ed25519 and X25519 keys.
///
/// Implements the `KeyCustodyProvider` callback interface defined in the
/// UniFFI bridge (`crates/scp-ffi/uniffi/src/bridge.rs`). Swift passes an
/// instance of this class into the Rust engine at `SCP.init()` time; all
/// signing and key-agreement operations are dispatched from Rust through the
/// UniFFI boundary into this class.
///
/// ## Key storage
///
/// Each key is stored as a `kSecClassGenericPassword` Keychain item:
/// - `kSecAttrAccount`: `"scp.key.<uuid>"` where `<uuid>` is the opaque handle.
/// - `kSecAttrLabel`: JSON-encoded ``KeyMetadata`` (type + cached public key).
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

    /// Runs inside `derivePseudonymKey` after the pseudonym item is stored and
    /// before the identity is checked again, with the identity handle. Tests
    /// use it to destroy the identity in that window; production passes `nil`.
    private let afterPseudonymStore: (@Sendable (_ identityHandle: String) -> Void)?

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
    public convenience init(accessGroup: String? = nil, biometricPolicy: BiometricPolicy = .none) {
        self.init(accessGroup: accessGroup, biometricPolicy: biometricPolicy, afterPseudonymStore: nil)
    }

    /// Creates a custody that runs `afterPseudonymStore` between a pseudonym's
    /// store and the identity re-check in `derivePseudonymKey`.
    init(
        accessGroup: String?,
        biometricPolicy: BiometricPolicy,
        afterPseudonymStore: (@Sendable (_ identityHandle: String) -> Void)?
    ) {
        self.accessGroup = accessGroup
        self.biometricPolicy = biometricPolicy
        self.afterPseudonymStore = afterPseudonymStore
    }

    // MARK: - Private Keychain helpers

    /// Upper bound on `SecItemDelete` calls in one pseudonym sweep. The
    /// file-based macOS keychain can delete one match per call; the bound
    /// keeps a concurrent deriver from holding the sweep in a loop, and the
    /// re-fetch after the sweep decides whether destruction is confirmed.
    private static let maxPseudonymSweeps = 4096

    /// `kSecAttrDescription` tag recording the biometric policy an item was
    /// stored under, so a re-store can tell whether the existing item's
    /// access control matches the current policy.
    private nonisolated var policyTag: String {
        "scp.policy.\(biometricPolicy.rawValue)"
    }

    /// `kSecAttrService` tag carried by every pseudonym item derived from
    /// `identityHandle`.
    private nonisolated func pseudonymOwnerTag(for identityHandle: String) -> String {
        "scp.pseudonym-of.\(identityHandle)"
    }

    /// Deletes every pseudonym item tagged with `identityHandle` and returns
    /// `true` only when a re-fetch finds none left.
    nonisolated func destroyPseudonyms(of identityHandle: String) throws -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: pseudonymOwnerTag(for: identityHandle)
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        for _ in 0 ..< Self.maxPseudonymSweeps {
            let status = SecItemDelete(query as CFDictionary)
            if status == errSecItemNotFound {
                break
            }
            guard status == errSecSuccess else { throw PlatformError.keychainError(status) }
        }
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecItemNotFound
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
    /// - Parameter handle: The opaque UUID handle returned by
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
    /// - Parameters:
    ///   - bytes: The raw 32-byte private key bytes.
    ///   - handle: The opaque UUID handle that will reference this key.
    ///   - keyType: The ``KeyType`` to tag this item with.
    ///   - publicKeyBytes: The public key bytes (33 bytes for a P-256 pseudonym) to cache in metadata.
    ///   - ownerIdentity: For a P-256 pseudonym, the identity handle it was
    ///     derived from; the item is tagged with it so that destroying the
    ///     identity also destroys the pseudonym (§9.10.4.A).
    /// - Throws: ``PlatformError/keychainError(_:)`` if the add operation fails.
    nonisolated func storePrivateKeyBytes(
        _ bytes: Data,
        for handle: String,
        keyType: KeyType,
        publicKeyBytes: Data,
        ownerIdentity: String? = nil
    ) throws {
        let metadata = KeyMetadata(
            keyType: keyType.rawValue,
            publicKeyBase64: publicKeyBytes.base64EncodedString()
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
        if let ownerIdentity {
            query[kSecAttrService as String] = pseudonymOwnerTag(for: ownerIdentity)
        }

        switch biometricPolicy {
        case .none:
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        case .required:
            query[kSecAttrAccessControl as String] = try biometricAccessControl(for: handle)
        }
        let status = SecItemAdd(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            break
        case errSecDuplicateItem:
            try keepOrReplaceExisting(handle: handle, query: query, ownerIdentity: ownerIdentity)
        default:
            throw PlatformError.keychainError(status)
        }
    }

    /// Resolves an `errSecDuplicateItem` from storing `query` under `handle`.
    ///
    /// Only a pseudonym (`ownerIdentity` set) has a deterministic handle: a
    /// re-derivation yields the same scalar, so an existing item stored under
    /// the current policy for the same owner already holds these bytes. It is
    /// kept, because deleting and re-adding would leave a window in which a
    /// concurrent `sign` finds no item. Any other item, and a pseudonym item
    /// stored under another policy, is replaced, so the new bytes and the
    /// current biometric policy apply.
    private nonisolated func keepOrReplaceExisting(
        handle: String,
        query: [String: Any],
        ownerIdentity: String?
    ) throws {
        if let ownerIdentity {
            var existing = baseQuery(for: handle)
            existing[kSecAttrDescription as String] = policyTag
            existing[kSecAttrService as String] = pseudonymOwnerTag(for: ownerIdentity)
            existing[kSecMatchLimit as String] = kSecMatchLimitOne
            let matchStatus = SecItemCopyMatching(existing as CFDictionary, nil)
            if matchStatus == errSecSuccess {
                return
            }
            guard matchStatus == errSecItemNotFound else {
                throw PlatformError.keychainError(matchStatus)
            }
        }
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

// MARK: - Pseudonym derivation

extension AppleKeyCustody {
    /// Shared §9.10.4.A derivation: `seedMessage` is the HMAC message after
    /// `pseudonym_secret` (v1 or v2), `handleMessage` the Keychain handle
    /// preimage. Stores the P-256 scalar and returns the compressed point.
    nonisolated func derivePseudonymKey(
        method: String,
        identityHandle: String,
        seedMessage: Data,
        handleMessage: Data
    ) throws -> PseudonymResult {
        let storedType = try fetchKeyType(for: identityHandle)
        guard storedType == .ed25519 else {
            throw PlatformError.wrongKeyType(
                "\(method) requires an Ed25519 key; handle '\(identityHandle)' is \(storedType.rawValue)"
            )
        }

        var identitySeed = try fetchPrivateKeyBytes(for: identityHandle)
        defer { identitySeed.resetBytes(in: 0 ..< identitySeed.count) }

        do {
            let pseudonymSecret = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: identitySeed),
                salt: Data("scp-pseudonym-secret-v1".utf8),
                info: Data(),
                outputByteCount: 32
            )
            var contextSeed = Data(HMAC<SHA256>.authenticationCode(
                for: seedMessage, using: pseudonymSecret
            ))
            defer { contextSeed.resetBytes(in: 0 ..< contextSeed.count) }

            var scalar = try P256Pseudonym.scalar(contextSeed: contextSeed)
            defer { scalar.resetBytes(in: 0 ..< scalar.count) }
            let publicKey = try P256Pseudonym.publicKey(scalar: scalar)

            // Deterministic handle: HMAC-SHA256(identity_handle_utf8, handleMessage).
            // Same inputs -> same handle -> same Keychain slot. No accumulation.
            let handle = Data(HMAC<SHA256>.authenticationCode(
                for: handleMessage, using: SymmetricKey(data: Data(identityHandle.utf8))
            )).map { String(format: "%02x", $0) }.joined()

            try storePrivateKeyBytes(
                scalar,
                for: handle,
                keyType: .p256Pseudonym,
                publicKeyBytes: publicKey,
                ownerIdentity: identityHandle
            )
            afterPseudonymStore?(identityHandle)
            // A destroyKey(identityHandle) that ran between the seed read and
            // the store has already swept this identity's pseudonyms, so this
            // item would outlive its identity: remove it and fail.
            do {
                _ = try fetchMetadata(for: identityHandle)
            } catch {
                _ = SecItemDelete(baseQuery(for: handle) as CFDictionary)
                throw error
            }
            return PseudonymResult(publicKey: publicKey, keyId: handle)
        } catch let platformErr as PlatformError {
            throw platformErr
        } catch {
            throw PlatformError.custodyError(
                "P-256 pseudonym key derivation failed: \(error.localizedDescription)"
            )
        }
    }
}

// MARK: - KeyCustodyProvider conformance

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
    /// - Parameter keyType: `"ed25519"` or `"x25519"`.
    /// - Returns: An opaque UUID string handle. Pass this to other methods on
    ///   this instance to perform operations with the key.
    /// - Throws: ``PlatformError/keychainError(_:)`` if the Keychain add fails,
    ///   ``PlatformError/custodyError(_:)`` for an unknown `keyType` string.
    ///
    /// See ADR-025 Key custody and ADR-006 `generate_keypair`.
    @concurrent
    func generateKeypair(keyType: String) async throws -> String {
        guard let parsedType = KeyType(rawValue: keyType), parsedType != .p256Pseudonym else {
            throw PlatformError.custodyError("Unknown key type '\(keyType)'")
        }

        let handle = UUID().uuidString
        let privateKeyBytes: Data
        let publicKeyBytes: Data

        switch parsedType {
        case .ed25519:
            let signingKey = Curve25519.Signing.PrivateKey()
            privateKeyBytes = signingKey.rawRepresentation
            publicKeyBytes = signingKey.publicKey.rawRepresentation
        case .x25519:
            let agreementKey = Curve25519.KeyAgreement.PrivateKey()
            privateKeyBytes = agreementKey.rawRepresentation
            publicKeyBytes = agreementKey.publicKey.rawRepresentation
        case .p256Pseudonym:
            throw PlatformError.custodyError("Unknown key type '\(keyType)'")
        }

        try storePrivateKeyBytes(
            privateKeyBytes, for: handle, keyType: parsedType, publicKeyBytes: publicKeyBytes
        )
        return handle
    }

    // MARK: sign

    /// Signs `data` with the Ed25519 or P-256 pseudonym key identified by
    /// `keyHandle`.
    ///
    /// An Ed25519 key returns a 64-byte Ed25519 signature over `data`. A P-256
    /// pseudonym key treats `data` as a 32-byte digest, signs it without a
    /// second hash, and returns the 64-byte `r || s` with low s (§9.5.1); any
    /// other length is rejected.
    ///
    /// The private key bytes are held in memory only for the duration of this
    /// call. They are not cached, logged, or returned across the FFI boundary.
    ///
    /// - Parameters:
    ///   - keyHandle: The UUID handle returned by ``generateKeypair(keyType:)``
    ///     for an `"ed25519"` key.
    ///   - data: The bytes to sign (a 32-byte digest for a pseudonym key).
    /// - Returns: A 64-byte signature.
    /// - Throws: ``PlatformError/wrongKeyType(_:)`` if `keyHandle` refers to
    ///   an X25519 key, ``PlatformError/keyNotFound(_:)`` if the handle is
    ///   unknown, ``PlatformError/biometricAuthenticationFailed(_:)`` if
    ///   biometric gating is active and authentication fails,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` if CryptoKit rejects Ed25519 key
    ///   bytes. For a P-256 pseudonym key the shared Rust helper's error
    ///   propagates unchanged: ``ScpError/Validation(msg:code:)`` with
    ///   `SCP-VALID-7005` if `data` or the stored scalar is not 32 bytes, and
    ///   ``ScpError/Crypto(msg:code:)`` with `SCP-CRYPTO-4001` if the scalar
    ///   is out of range.
    ///
    /// See ADR-025 Key custody and ADR-006 `sign`.
    @concurrent
    func sign(_ keyHandle: String, data: Data) async throws -> Data {
        let storedType = try fetchKeyType(for: keyHandle)
        guard storedType != .x25519 else {
            throw PlatformError.wrongKeyType(
                "sign requires a signing key; handle '\(keyHandle)' is X25519"
            )
        }

        var privateKeyBytes = try fetchPrivateKeyBytes(for: keyHandle)
        defer { privateKeyBytes.resetBytes(in: 0 ..< privateKeyBytes.count) }

        do {
            if storedType == .p256Pseudonym {
                return try P256Pseudonym.signPrehash(scalar: privateKeyBytes, digest: data)
            }
            let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
            return try signingKey.signature(for: data)
        } catch let platformErr as PlatformError {
            throw platformErr
        } catch let scpErr as ScpError {
            // The shared P-256 helper's typed error and code reach the caller
            // unchanged, as in the Kotlin SDK.
            throw scpErr
        } catch {
            throw PlatformError.custodyError(
                "\(storedType == .p256Pseudonym ? "P-256 pseudonym" : "Ed25519") signing failed for handle "
                    + "'\(keyHandle)': \(error.localizedDescription)"
            )
        }
    }

    // MARK: publicKey

    /// Returns the public key for any key handle: 32 bytes for Ed25519 and
    /// X25519, the 33-byte compressed point for a P-256 pseudonym key.
    ///
    /// Reads the cached public key from Keychain metadata attributes. This
    /// does NOT access key material and therefore does NOT trigger biometric
    /// prompts on gated keys. Falls back to private-key derivation for legacy
    /// items that predate the metadata cache.
    ///
    /// - Parameter keyHandle: The UUID handle returned by
    ///   ``generateKeypair(keyType:)`` or ``derivePseudonym(_:contextId:)``.
    /// - Returns: The raw public key bytes.
    /// - Throws: ``PlatformError/keyNotFound(_:)`` if the handle is unknown,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` if CryptoKit rejects the key bytes.
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
           pubKeyData.count == (keyType == .p256Pseudonym ? 33 : 32) {
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
            case .p256Pseudonym:
                return try P256Pseudonym.publicKey(scalar: privateKeyBytes)
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

    /// Deletes the Keychain item for `keyHandle`, and every P-256 pseudonym
    /// derived from it, and returns a destruction attestation after
    /// confirming that none of them remain.
    ///
    /// ## Deletion verification
    ///
    /// After `SecItemDelete` succeeds, this method performs a re-fetch to
    /// confirm the item is no longer present. If the item still exists (i.e.,
    /// the re-fetch returns anything other than `errSecItemNotFound`), the
    /// method throws ``PlatformError/destructionFailed(_:)``. The same holds
    /// for the pseudonym items tagged with `keyHandle`: they are deleted
    /// whether or not the identity item was found, and any survivor fails
    /// the destruction.
    ///
    /// ## Attestation
    ///
    /// Returns a ``DestructionAttestation`` with `method: .softwareOnly` and
    /// `confirmed: true`. The `.softwareOnly` method reflects that Keychain
    /// keys have no hardware-level destruction guarantee -- contrast with App
    /// Attest P-256 keys managed by `DCAppAttestService`. See 9.15 of the
    /// SCP specification.
    ///
    /// - Parameter keyHandle: The UUID handle returned by
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
        let pseudonymsGone = try destroyPseudonyms(of: keyHandle)

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

        guard verifyStatus == errSecItemNotFound, pseudonymsGone else {
            // An item is still present -- destruction cannot be confirmed.
            throw PlatformError.destructionFailed(keyHandle)
        }

        return DestructionAttestation(method: .softwareOnly, confirmed: true)
    }

    // MARK: dhAgree

    /// Performs X25519 Diffie-Hellman key agreement.
    ///
    /// Retrieves the X25519 private key bytes from Keychain and computes the
    /// shared secret with `peerPublic`. The private key never crosses the
    /// `AppleKeyCustody` boundary -- the scalar multiplication happens entirely
    /// within this method.
    ///
    /// - Parameters:
    ///   - keyHandle: The UUID handle returned by ``generateKeypair(keyType:)``
    ///     for an `"x25519"` key.
    ///   - peerPublic: The 32-byte X25519 public key of the peer.
    /// - Returns: 32-byte X25519 shared secret.
    /// - Throws: ``PlatformError/wrongKeyType(_:)`` if `keyHandle` refers to
    ///   an Ed25519 key, ``PlatformError/keyNotFound(_:)`` if the handle is
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
        guard storedType == .x25519 else {
            throw PlatformError.wrongKeyType(
                "dhAgree requires an X25519 key; handle '\(keyHandle)' is Ed25519"
            )
        }

        var privateKeyBytes = try fetchPrivateKeyBytes(for: keyHandle)
        defer { privateKeyBytes.resetBytes(in: 0 ..< privateKeyBytes.count) }

        do {
            let agreementKey = try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: privateKeyBytes
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
    /// Ed25519 identity key (spec §9.10.4.A).
    ///
    /// ## Algorithm
    /// 1. Retrieve the Ed25519 private seed for `keyHandle` from Keychain.
    ///    Native software custody keys the recipe on this seed until slice
    ///    S12 (§9.10.4 native interim).
    /// 2. `pseudonym_secret = HKDF-SHA256(ikm: seed,
    ///    salt: "scp-pseudonym-secret-v1", info: "", len: 32)`.
    /// 3. `context_seed = HMAC-SHA256(pseudonym_secret, contextId || "scp-pseudonym")`.
    /// 4. `d = HKDF-Expand-SHA256(prk: context_seed, info: "SCP-PSEUDONYM-P256-V1",
    ///    48) mod (n - 1) + 1`.
    /// 5. Store `d` in Keychain as a ``KeyType/p256Pseudonym`` key under a
    ///    deterministic handle.
    /// 6. Return the 33-byte compressed point `d * G` and the handle.
    ///
    /// **CRITICAL:** The HMAC key is derived from the private seed. Keying it
    /// on the public key would be a membership-enumeration oracle: anyone who
    /// knows a member's public key could compute their pseudonym for any
    /// context and check relay subscriptions.
    ///
    /// - Parameters:
    ///   - keyHandle: The handle of the **identity** Ed25519 key.
    ///   - contextId: The raw context ID bytes.
    /// - Returns: A ``PseudonymResult`` whose `publicKey` is the 33-byte
    ///   compressed P-256 point and whose `keyId` is the pseudonym key handle.
    /// - Throws: ``PlatformError/wrongKeyType(_:)`` if `keyHandle` is not an
    ///   Ed25519 key, ``PlatformError/keyNotFound(_:)`` if the handle is
    ///   unknown, ``PlatformError/biometricAuthenticationFailed(_:)`` if
    ///   biometric gating is active and authentication fails,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` for key derivation failures.
    ///
    /// See spec §9.10.4.A and `derive_pseudonym_keypair` in
    /// `scp-crypto/src/pseudonym.rs` for the Rust reference.
    @concurrent
    func derivePseudonym(
        _ keyHandle: String,
        contextId: Data
    ) async throws -> PseudonymResult {
        var message = contextId
        message.append(Data("scp-pseudonym".utf8))
        var handleMessage = contextId
        handleMessage.append(Data("scp-pseudonym-handle".utf8))
        return try derivePseudonymKey(
            method: "derivePseudonym",
            identityHandle: keyHandle,
            seedMessage: message,
            handleMessage: handleMessage
        )
    }

    // MARK: deriveRotatablePseudonym

    /// Derives the deterministic, context-scoped, epoch-rotatable P-256
    /// pseudonym of an Ed25519 identity key (rotation per spec §9.10.4.1,
    /// derivation per §9.10.4.A).
    ///
    /// Identical to ``derivePseudonym(_:contextId:)`` except step 3:
    /// `context_seed = HMAC-SHA256(pseudonym_secret,
    /// contextId || BE64(pseudonymEpoch) || "scp-pseudonym-v2")`. The handle
    /// also binds the epoch and `"v2"`, so each epoch occupies its own
    /// Keychain slot, distinct from the v1 handle.
    ///
    /// - Parameters:
    ///   - keyHandle: The handle of the **identity** Ed25519 key.
    ///   - contextId: The raw context ID bytes.
    ///   - pseudonymEpoch: The rotation epoch, serialized as 8 big-endian bytes.
    /// - Returns: A ``PseudonymResult`` whose `publicKey` is the 33-byte
    ///   compressed P-256 point and whose `keyId` is the pseudonym key handle.
    /// - Throws: The same errors as ``derivePseudonym(_:contextId:)``.
    @concurrent
    func deriveRotatablePseudonym(
        _ keyHandle: String,
        contextId: Data,
        pseudonymEpoch: UInt64
    ) async throws -> PseudonymResult {
        // Epoch serialized as 8 big-endian bytes (matches Rust `u64::to_be_bytes`).
        let epochBytes = withUnsafeBytes(of: pseudonymEpoch.bigEndian) { Data($0) }
        var message = contextId
        message.append(epochBytes)
        message.append(Data("scp-pseudonym-v2".utf8))
        var handleMessage = contextId
        handleMessage.append(epochBytes)
        handleMessage.append(Data("scp-pseudonym-handle-v2".utf8))
        return try derivePseudonymKey(
            method: "deriveRotatablePseudonym",
            identityHandle: keyHandle,
            seedMessage: message,
            handleMessage: handleMessage
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
    /// - Parameter keyId: The UUID handle returned by
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
    /// - Parameter keyHandle: The UUID handle (not inspected; the custody type
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
