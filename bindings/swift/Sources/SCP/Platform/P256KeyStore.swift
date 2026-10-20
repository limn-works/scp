import Foundation
import Security

// MARK: - P256KeyStore

/// The store that holds the private half of every P-256 key
/// ``AppleKeyCustody`` mints (`p256` signing keys and `hpke-p256` wrapping
/// keys) and runs every operation on it.
///
/// ADR-025 criterion 8 requires the private key to live in the Secure Enclave
/// and every signature and ECDH agreement to run there, with no software
/// fallback. ``SecureEnclaveP256KeyStore`` is the only implementation the SDK
/// ships, and the public ``AppleKeyCustody`` initializer always uses it. The
/// seam exists so that a test can run the adapter's P-256 paths on a host
/// without an enclave; no production code path can choose another store.
///
/// A key is addressed by its application tag, the UTF-8 bytes of
/// `"scp.key.<id>"`. Every method takes and returns `Data`, so no `SecKey`
/// crosses an isolation boundary.
protocol P256KeyStore: Sendable {
    /// Creates a key under `tag` gated by `policy` and returns its 65-byte
    /// uncompressed SEC1 public key (`04 || X || Y`).
    ///
    /// - Throws: ``PlatformError/secureEnclaveUnavailable(_:)`` when the
    ///   store cannot create the key; no key is left behind.
    func create(tag: Data, policy: BiometricPolicy) async throws -> Data

    /// The 65-byte uncompressed public key of the key under `tag`.
    ///
    /// - Throws: ``PlatformError/keyNotFound(_:)`` when no key has `tag`.
    func publicKey(tag: Data) async throws -> Data

    /// The DER `ECDSA-Sig-Value` the key under `tag` produces over the
    /// 32-byte `digest`, which is signed as given and not hashed again.
    func sign(tag: Data, digest: Data) async throws -> Data

    /// The 32-byte ECDH shared secret (the x-coordinate) of the key under
    /// `tag` and `peer`, a 65-byte uncompressed point the caller has already
    /// validated as on the curve.
    func agree(tag: Data, peer: Data) async throws -> Data

    /// Deletes the key under `tag`. Returns `false` when no key had `tag`.
    func delete(tag: Data) async throws -> Bool

    /// Whether a key has `tag`.
    func contains(tag: Data) async throws -> Bool
}

// MARK: - SecureEnclaveP256KeyStore

/// The production ``P256KeyStore``: every key is generated inside the Secure
/// Enclave through `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`
/// and never leaves it (ADR-025 criterion 8).
///
/// Each key is a permanent `kSecClassKey` item tagged with its application
/// tag and stored under the adapter's access group (ADR-025 criterion 2). On
/// macOS every add, lookup and delete sets `kSecUseDataProtectionKeychain`,
/// because an enclave key exists only in the data-protection keychain and a
/// query without the flag searches the file keychain, finds nothing, and
/// would report a live key as destroyed.
///
/// Where no enclave is reachable (the simulator, a virtual machine, an Intel
/// Mac without a T2 chip, a binary without the keychain entitlement)
/// ``create(tag:policy:)`` throws ``PlatformError/secureEnclaveUnavailable(_:)``
/// and nothing falls back to a software key.
nonisolated struct SecureEnclaveP256KeyStore: P256KeyStore {
    /// The Keychain access group every key item is stored under, or `nil`
    /// for the process default.
    let accessGroup: String?

    /// The query that selects the enclave key under `tag`.
    private func keyQuery(tag: Data) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        #if os(macOS)
            query[kSecUseDataProtectionKeychain as String] = true
        #endif
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    /// The access control of a new key: `.privateKeyUsage` always, plus
    /// `.biometryCurrentSet` under ``BiometricPolicy/required``. The
    /// protection class is `AfterFirstUnlockThisDeviceOnly` without a
    /// biometric gate (ADR-025 criterion 2) and `WhenUnlockedThisDeviceOnly`
    /// with one, as for the adapter's other biometric-gated items.
    private func accessControl(for policy: BiometricPolicy) throws -> SecAccessControl {
        let protection: CFString
        let flags: SecAccessControlCreateFlags
        switch policy {
        case .none:
            protection = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            flags = [.privateKeyUsage]
        case .required:
            protection = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            flags = [.privateKeyUsage, .biometryCurrentSet]
        }
        var cfError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, protection, flags, &cfError) else {
            throw PlatformError.custodyError(
                "Failed to create Secure Enclave access control: \(Self.describe(cfError))"
            )
        }
        return access
    }

    func create(tag: Data, policy: BiometricPolicy) throws -> Data {
        var privateAttributes: [String: Any] = try [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: accessControl(for: policy)
        ]
        if let accessGroup {
            privateAttributes[kSecAttrAccessGroup as String] = accessGroup
        }
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateAttributes
        ]
        #if os(macOS)
            attributes[kSecUseDataProtectionKeychain as String] = true
        #endif
        if let accessGroup {
            attributes[kSecAttrAccessGroup as String] = accessGroup
        }

        var cfError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) else {
            throw PlatformError.secureEnclaveUnavailable(Self.status(cfError))
        }
        do {
            return try Self.uncompressedPublicKey(of: key)
        } catch {
            // A key whose public half cannot be read is unusable; remove it so
            // the failed generation leaves nothing behind.
            SecItemDelete(keyQuery(tag: tag) as CFDictionary)
            throw error
        }
    }

    /// Loads the private key reference under `tag`. The reference is a
    /// handle to the enclave key, not its bytes.
    private func load(tag: Data) throws -> SecKey {
        var query = keyQuery(tag: tag)
        query[kSecReturnRef as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let result, CFGetTypeID(result) == SecKeyGetTypeID() else {
                throw PlatformError.custodyError("Keychain returned no key reference")
            }
            // The type id check above makes this cast exact.
            return result as! SecKey // swiftlint:disable:this force_cast
        case errSecItemNotFound:
            throw PlatformError.keyNotFound(Self.handle(of: tag))
        default:
            throw PlatformError.keychainError(status)
        }
    }

    func publicKey(tag: Data) throws -> Data {
        try Self.uncompressedPublicKey(of: load(tag: tag))
    }

    func sign(tag: Data, digest: Data) throws -> Data {
        let key = try load(tag: tag)
        var cfError: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            key, .ecdsaSignatureDigestX962SHA256, digest as CFData, &cfError
        ) else {
            throw Self.operationError("Secure Enclave signing", tag: tag, cfError)
        }
        return der as Data
    }

    func agree(tag: Data, peer: Data) throws -> Data {
        let key = try load(tag: tag)
        let peerKey = try Self.peerKey(peer)
        var cfError: Unmanaged<CFError>?
        guard let secret = SecKeyCopyKeyExchangeResult(
            key, .ecdhKeyExchangeStandard, peerKey, [:] as CFDictionary, &cfError
        ) else {
            throw Self.operationError("Secure Enclave ECDH", tag: tag, cfError)
        }
        return secret as Data
    }

    func delete(tag: Data) throws -> Bool {
        let status = SecItemDelete(keyQuery(tag: tag) as CFDictionary)
        switch status {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return false
        default:
            throw PlatformError.keychainError(status)
        }
    }

    func contains(tag: Data) throws -> Bool {
        var query = keyQuery(tag: tag)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return false
        default:
            throw PlatformError.keychainError(status)
        }
    }
}

// MARK: - Shared SecKey helpers

extension SecureEnclaveP256KeyStore {
    /// The 65-byte uncompressed SEC1 public key of a P-256 private key.
    static func uncompressedPublicKey(of key: SecKey) throws -> Data {
        var cfError: Unmanaged<CFError>?
        guard
            let publicKey = SecKeyCopyPublicKey(key),
            let external = SecKeyCopyExternalRepresentation(publicKey, &cfError) as Data?
        else {
            throw PlatformError.custodyError(
                "Failed to export the P-256 public key: \(describe(cfError))"
            )
        }
        guard external.count == 65, external.first == 0x04 else {
            throw PlatformError.custodyError(
                "P-256 public key export returned \(external.count) bytes, expected 65"
            )
        }
        return external
    }

    /// A public `SecKey` for a 65-byte uncompressed peer point.
    static func peerKey(_ peer: Data) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var cfError: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(peer as CFData, attributes as CFDictionary, &cfError) else {
            throw PlatformError.custodyError("Invalid P-256 peer public key: \(describe(cfError))")
        }
        return key
    }

    /// The key id an application tag names, for error messages.
    static func handle(of tag: Data) -> String {
        let text = String(bytes: tag, encoding: .utf8) ?? tag.base64EncodedString()
        let prefix = "scp.key."
        return text.hasPrefix(prefix) ? String(text.dropFirst(prefix.count)) : text
    }

    /// The `OSStatus` a Security framework `CFError` carries.
    static func status(_ cfError: Unmanaged<CFError>?) -> OSStatus {
        guard let cfError else { return errSecInternalError }
        return OSStatus(truncatingIfNeeded: CFErrorGetCode(cfError.takeRetainedValue()))
    }

    /// A readable description of a Security framework `CFError`.
    static func describe(_ cfError: Unmanaged<CFError>?) -> String {
        cfError.map { ($0.takeRetainedValue() as Error).localizedDescription } ?? "unknown error"
    }

    /// The typed error of a failed enclave operation: a cancelled or failed
    /// user authentication is ``PlatformError/biometricAuthenticationFailed(_:)``,
    /// anything else ``PlatformError/custodyError(_:)``.
    static func operationError(
        _ operation: String,
        tag: Data,
        _ cfError: Unmanaged<CFError>?
    ) -> PlatformError {
        guard let cfError else {
            return .custodyError("\(operation) failed for key id '\(handle(of: tag))'")
        }
        let error = cfError.takeRetainedValue()
        let code = OSStatus(truncatingIfNeeded: CFErrorGetCode(error))
        let detail = (error as Error).localizedDescription
        switch code {
        case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
            return .biometricAuthenticationFailed(
                "\(operation) for key id '\(handle(of: tag))' (OSStatus \(code)): \(detail)"
            )
        default:
            return .custodyError("\(operation) failed for key id '\(handle(of: tag))': \(detail)")
        }
    }
}
