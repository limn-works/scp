// An in-process `P256KeyStore` for running `AppleKeyCustody`'s P-256 paths on
// a `swift test` host. An unsigned test binary can neither create a Secure
// Enclave key nor write the data-protection keychain the production
// `KeychainP256KeyStore` uses for both backings (`errSecMissingEntitlement`),
// so the adapter's P-256 logic runs against this store instead. It lives in
// the test target only: the SDK's public `AppleKeyCustody` initializer always
// builds `KeychainP256KeyStore`, so no shipped code path can reach this store.
//
// Keys are non-permanent `SecKey`s built with `SecKeyCreateRandomKey` without
// a token id, and every operation uses the same Security framework calls as
// the production store (`.ecdsaSignatureDigestX962SHA256`, which emits DER,
// and `.ecdhKeyExchangeStandard`), so the adapter sees the same output shapes.
// Fault switches make the store fail the way a real Keychain can.

#if os(iOS) || os(macOS)

    import Foundation
    @testable import SCP
    import Security

    actor SoftwareP256KeyStore: P256KeyStore {
        private var keys: [Data: SecKey] = [:]
        /// How many times `agree` reached a key, so a test can prove the
        /// adapter refused a peer before the agreement ran.
        private(set) var agreeCalls = 0
        /// How many keys `create` made, so a test can prove nothing was
        /// generated.
        private(set) var createCalls = 0
        /// The biometric policy of every `create`, in order.
        private(set) var policies: [BiometricPolicy] = []
        /// When set, `delete` reports success but keeps the key, as a store
        /// whose deletion silently failed would.
        private var deleteKeepsKey = false
        /// When set, `create` throws this error and makes no key.
        private var createError: PlatformError?
        /// How many upcoming `delete` calls throw instead of deleting.
        private var failingDeletes = 0
        /// When set, `create` keeps the key it made but returns a 65-byte
        /// point that is not on the curve, so the mint fails after creation.
        private var returnsInvalidPoint = false

        func keepKeysOnDelete(_ keep: Bool) {
            deleteKeepsKey = keep
        }

        func failCreate(with error: PlatformError?) {
            createError = error
        }

        func failNextDeletes(_ count: Int) {
            failingDeletes = count
        }

        func returnInvalidPoint(_ invalid: Bool) {
            returnsInvalidPoint = invalid
        }

        /// Adds a key under `tag` without going through the adapter, as an
        /// orphan left by an interrupted mint would be.
        func plant(tag: Data) throws {
            keys[tag] = try Self.newKey()
        }

        private static func newKey() throws -> SecKey {
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]
            ]
            var cfError: Unmanaged<CFError>?
            guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) else {
                throw PlatformError.custodyError("software P-256 key generation failed")
            }
            return key
        }

        func create(tag: Data, policy: BiometricPolicy) throws -> Data {
            policies.append(policy)
            if let createError {
                throw createError
            }
            let key = try Self.newKey()
            createCalls += 1
            keys[tag] = key
            if returnsInvalidPoint {
                return Data([0x04]) + Data(repeating: 0x01, count: 64)
            }
            return try KeychainP256KeyStore.uncompressedPublicKey(of: key)
        }

        private func key(_ tag: Data) throws -> SecKey {
            guard let key = keys[tag] else {
                throw PlatformError.keyNotFound(KeychainP256KeyStore.handle(of: tag))
            }
            return key
        }

        func publicKey(tag: Data) throws -> Data {
            try KeychainP256KeyStore.uncompressedPublicKey(of: key(tag))
        }

        func sign(tag: Data, digest: Data) throws -> Data {
            var cfError: Unmanaged<CFError>?
            guard let der = try SecKeyCreateSignature(
                key(tag), .ecdsaSignatureDigestX962SHA256, digest as CFData, &cfError
            ) else {
                throw KeychainP256KeyStore.operationError("software P-256 signing", tag: tag, cfError)
            }
            return der as Data
        }

        func agree(tag: Data, peer: Data) throws -> Data {
            agreeCalls += 1
            let peerKey = try KeychainP256KeyStore.peerKey(peer)
            var cfError: Unmanaged<CFError>?
            guard let secret = try SecKeyCopyKeyExchangeResult(
                key(tag), .ecdhKeyExchangeStandard, peerKey, [:] as CFDictionary, &cfError
            ) else {
                throw KeychainP256KeyStore.operationError("software P-256 ECDH", tag: tag, cfError)
            }
            return secret as Data
        }

        func delete(tag: Data) throws -> Bool {
            if failingDeletes > 0 {
                failingDeletes -= 1
                throw PlatformError.keychainError(errSecInteractionNotAllowed)
            }
            if deleteKeepsKey {
                return keys[tag] != nil
            }
            return keys.removeValue(forKey: tag) != nil
        }

        func contains(tag: Data) -> Bool {
            keys[tag] != nil
        }
    }

#endif // os(iOS) || os(macOS)
