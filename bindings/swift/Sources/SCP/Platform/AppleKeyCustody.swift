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
        case .keychainError(let status):
            "Keychain operation failed with OSStatus \(status)"
        case .keyNotFound(let handle):
            "Key not found for handle '\(handle)'"
        case .wrongKeyType(let detail):
            "Wrong key type: \(detail)"
        case .destructionFailed(let handle):
            "Key destruction failed: item persisted for handle '\(handle)'"
        case .biometricAuthenticationFailed(let detail):
            "Biometric authentication failed: \(detail)"
        case .custodyError(let message):
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
    /// Ed25519 signing key. Used for identity keys, active signing keys, and
    /// pseudonym keys. Private bytes are 32 bytes; public bytes are 32 bytes.
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

// MARK: - PseudonymResult

/// The result of a pseudonym derivation operation.
///
/// Contains the 32-byte Ed25519 public key of the derived pseudonym and an
/// opaque handle (UUID string) for the stored pseudonym signing key. The
/// handle can be used with ``AppleKeyCustody/sign(_:data:)`` to produce
/// pseudonym-signed messages.
///
/// See ADR-006 for the derivation algorithm and ADR-025 for the implementation
/// on Apple platforms.
public nonisolated struct PseudonymResult: Sendable {
    /// The 32-byte Ed25519 public key of the derived pseudonym.
    public nonisolated let publicKey: Data
    /// Opaque UUID handle to the derived signing key stored in Keychain.
    public nonisolated let handle: String

    /// Memberwise initializer.
    public nonisolated init(publicKey: Data, handle: String) {
        self.publicKey = publicKey
        self.handle = handle
    }
}

// MARK: - KeyMetadata

/// Internal metadata stored alongside a Keychain key item.
///
/// Encoded as a compact JSON blob and stored in `kSecAttrLabel`. This allows
/// type-checking and public key retrieval without accessing key material
/// (which would trigger biometric prompts on gated keys).
private nonisolated struct KeyMetadata: Codable, Sendable {
    /// The ``KeyType`` of the stored key.
    let keyType: String
    /// Base64-encoded 32-byte public key bytes, stored at generation time.
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
    internal let biometricPolicy: BiometricPolicy

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

    /// Builds a base Keychain query dictionary for a key handle.
    ///
    /// All operations (add, fetch, delete) start from this base and extend it
    /// with operation-specific keys.
    private nonisolated func baseQuery(for handle: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account(for: handle),
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
    ///   - publicKeyBytes: The 32-byte public key bytes to cache in metadata.
    /// - Throws: ``PlatformError/keychainError(_:)`` if the add operation fails.
    internal nonisolated func storePrivateKeyBytes(
        _ bytes: Data,
        for handle: String,
        keyType: KeyType,
        publicKeyBytes: Data
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

        switch biometricPolicy {
        case .none:
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        case .required:
            // Create a SecAccessControl requiring the currently enrolled biometric
            // set. `.biometryCurrentSet` invalidates access if biometrics change
            // (new fingerprint enrolled, Face ID reset), which triggers key
            // rotation per 9.12. Falls back to device passcode on hardware
            // without biometric sensors.
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
            query[kSecAttrAccessControl as String] = accessControl
        }

        let status = SecItemAdd(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            break
        case errSecDuplicateItem:
            // For deterministic handles (pseudonym derivation), the item may
            // already exist with different access control. Delete and re-add
            // to ensure correct biometric policy is applied.
            let deleteStatus = SecItemDelete(baseQuery(for: handle) as CFDictionary)
            guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
                throw PlatformError.keychainError(deleteStatus)
            }
            let retryStatus = SecItemAdd(query as CFDictionary, nil)
            guard retryStatus == errSecSuccess else {
                throw PlatformError.keychainError(retryStatus)
            }
        default:
            throw PlatformError.keychainError(status)
        }
    }
}

// MARK: - KeyCustodyProvider conformance

extension AppleKeyCustody {
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
    public func generateKeypair(keyType: String) async throws -> String {
        guard let parsedType = KeyType(rawValue: keyType) else {
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
        }

        try storePrivateKeyBytes(
            privateKeyBytes, for: handle, keyType: parsedType, publicKeyBytes: publicKeyBytes
        )
        return handle
    }

    // MARK: sign

    /// Signs `data` with the Ed25519 key identified by `keyHandle`.
    ///
    /// Retrieves the private key bytes from Keychain and constructs an
    /// `ed25519_dalek`-compatible signing key. Returns a 64-byte Ed25519
    /// signature.
    ///
    /// The private key bytes are held in memory only for the duration of this
    /// call. They are not cached, logged, or returned across the FFI boundary.
    ///
    /// - Parameters:
    ///   - keyHandle: The UUID handle returned by ``generateKeypair(keyType:)``
    ///     for an `"ed25519"` key.
    ///   - data: The bytes to sign.
    /// - Returns: 64-byte Ed25519 signature.
    /// - Throws: ``PlatformError/wrongKeyType(_:)`` if `keyHandle` refers to
    ///   an X25519 key, ``PlatformError/keyNotFound(_:)`` if the handle is
    ///   unknown, ``PlatformError/biometricAuthenticationFailed(_:)`` if
    ///   biometric gating is active and authentication fails,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` if CryptoKit rejects the key bytes.
    ///
    /// See ADR-025 Key custody and ADR-006 `sign`.
    @concurrent
    public func sign(_ keyHandle: String, data: Data) async throws -> Data {
        let storedType = try fetchKeyType(for: keyHandle)
        guard storedType == .ed25519 else {
            throw PlatformError.wrongKeyType(
                "sign requires an Ed25519 key; handle '\(keyHandle)' is X25519"
            )
        }

        var privateKeyBytes = try fetchPrivateKeyBytes(for: keyHandle)
        defer { privateKeyBytes.resetBytes(in: 0..<privateKeyBytes.count) }

        do {
            let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
            let signature = try signingKey.signature(for: data)
            return signature
        } catch let platformErr as PlatformError {
            throw platformErr
        } catch {
            throw PlatformError.custodyError(
                "Ed25519 signing failed for handle '\(keyHandle)': \(error.localizedDescription)"
            )
        }
    }

    // MARK: publicKey

    /// Returns the 32-byte public key for any key handle (Ed25519 or X25519).
    ///
    /// Reads the cached public key from Keychain metadata attributes. This
    /// does NOT access key material and therefore does NOT trigger biometric
    /// prompts on gated keys. Falls back to private-key derivation for legacy
    /// items that predate the metadata cache.
    ///
    /// - Parameter keyHandle: The UUID handle returned by
    ///   ``generateKeypair(keyType:)`` or ``derivePseudonym(_:contextId:)``.
    /// - Returns: 32-byte raw public key bytes.
    /// - Throws: ``PlatformError/keyNotFound(_:)`` if the handle is unknown,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` if CryptoKit rejects the key bytes.
    ///
    /// See ADR-025 Key custody and ADR-006 `public_key`.
    @concurrent
    public func publicKey(_ keyHandle: String) async throws -> Data {
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
        defer { privateKeyBytes.resetBytes(in: 0..<privateKeyBytes.count) }

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
    /// attestation after confirming the item is gone.
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
    public func destroyKey(_ keyHandle: String) async throws -> DestructionAttestation {
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
            // Item still present -- destruction cannot be confirmed.
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
    public func dhAgree(_ keyHandle: String, peerPublic: Data) async throws -> Data {
        let storedType = try fetchKeyType(for: keyHandle)
        guard storedType == .x25519 else {
            throw PlatformError.wrongKeyType(
                "dhAgree requires an X25519 key; handle '\(keyHandle)' is Ed25519"
            )
        }

        var privateKeyBytes = try fetchPrivateKeyBytes(for: keyHandle)
        defer { privateKeyBytes.resetBytes(in: 0..<privateKeyBytes.count) }

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

    /// Derives a deterministic, context-scoped Ed25519 pseudonym keypair.
    ///
    /// ## Algorithm (ADR-006, ADR-027 amendment):
    /// 1. Retrieve the Ed25519 private key bytes for `keyHandle` from Keychain.
    /// 2. Derive the Ed25519 public key from the private key.
    /// 3. Compute `seed = HMAC-SHA256(public_key_bytes, contextId || "scp-pseudonym")`.
    ///    **ADR-027: uses public key bytes as HMAC key** for cross-platform
    ///    determinism with hardware TEE adapters (e.g., Android Keystore)
    ///    that cannot export private key material.
    /// 4. Derive an Ed25519 keypair from the first 32 bytes of `seed`.
    /// 5. Store the derived private key in Keychain under a deterministic handle.
    /// 6. Return a ``PseudonymResult`` with the 32-byte public key and the handle.
    ///
    /// The derivation is deterministic: the same `keyHandle` + `contextId`
    /// pair always produces the same pseudonym public key.
    ///
    /// - Parameters:
    ///   - keyHandle: The UUID handle for the **identity** Ed25519 key (source
    ///     key material for the derivation).
    ///   - contextId: The raw context ID bytes used as the HMAC message.
    /// - Returns: A ``PseudonymResult`` containing the 32-byte pseudonym public
    ///   key and an opaque UUID handle to the derived signing key in Keychain.
    /// - Throws: ``PlatformError/wrongKeyType(_:)`` if `keyHandle` is X25519,
    ///   ``PlatformError/keyNotFound(_:)`` if the handle is unknown,
    ///   ``PlatformError/biometricAuthenticationFailed(_:)`` if biometric
    ///   gating is active and authentication fails,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` for HMAC or keygen failures.
    ///
    /// See ADR-025 Key custody, ADR-006 `derive_pseudonym`, ADR-027 amendment,
    /// and `InMemoryKeyCustody.derive_pseudonym` in
    /// `scp-platform/src/testing/key_custody.rs` for the canonical Rust
    /// reference implementation.
    @concurrent
    public func derivePseudonym(
        _ keyHandle: String,
        contextId: Data
    ) async throws -> PseudonymResult {
        let storedType = try fetchKeyType(for: keyHandle)
        guard storedType == .ed25519 else {
            throw PlatformError.wrongKeyType(
                "derivePseudonym requires an Ed25519 key; handle '\(keyHandle)' is X25519"
            )
        }

        var privateKeyBytes = try fetchPrivateKeyBytes(for: keyHandle)
        defer { privateKeyBytes.resetBytes(in: 0..<privateKeyBytes.count) }

        do {
            // ADR-027: use public key bytes as HMAC key for cross-platform
            // determinism with hardware TEE adapters that cannot export
            // private key material.
            let identityKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
            let publicKeyBytes = identityKey.publicKey.rawRepresentation

            // HMAC-SHA256(ed25519_public_key_bytes, contextId || "scp-pseudonym")
            let hmacKey = SymmetricKey(data: publicKeyBytes)
            var hmac = HMAC<SHA256>(key: hmacKey)
            hmac.update(data: contextId)
            hmac.update(data: Data("scp-pseudonym".utf8))
            let seed = Data(hmac.finalize())

            // Derive Ed25519 keypair from the 32-byte HMAC-SHA256 output.
            let pseudonymKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed.prefix(32))
            let pseudonymPublicKey = pseudonymKey.publicKey.rawRepresentation

            // Deterministic handle: HMAC-SHA256(key_handle_utf8, contextId || "scp-pseudonym-handle")
            // Same inputs -> same handle -> same Keychain slot. No accumulation.
            let handleHmacKey = SymmetricKey(data: Data(keyHandle.utf8))
            var handleHmac = HMAC<SHA256>(key: handleHmacKey)
            handleHmac.update(data: contextId)
            handleHmac.update(data: Data("scp-pseudonym-handle".utf8))
            let pseudonymHandle = Data(handleHmac.finalize()).map { String(format: "%02x", $0) }.joined()

            try storePrivateKeyBytes(
                pseudonymKey.rawRepresentation,
                for: pseudonymHandle,
                keyType: .ed25519,
                publicKeyBytes: pseudonymPublicKey
            )

            return PseudonymResult(publicKey: pseudonymPublicKey, handle: pseudonymHandle)
        } catch let platformErr as PlatformError {
            throw platformErr
        } catch {
            throw PlatformError.custodyError(
                "Ed25519 pseudonym key derivation failed: \(error.localizedDescription)"
            )
        }
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
    public nonisolated func custodyType(_ keyHandle: String) -> String {
        switch biometricPolicy {
        case .none: "software"
        case .required: "software_biometric"
        }
    }
}
