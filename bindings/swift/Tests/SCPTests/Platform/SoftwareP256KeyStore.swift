// A software `P256KeyStore` for running `AppleKeyCustody`'s P-256 paths on a
// `swift test` host, which holds no Secure Enclave key it can generate under
// an app entitlement (ADR-025 criterion 7). It lives in the test target only:
// the SDK's public `AppleKeyCustody` initializer always uses
// `SecureEnclaveP256KeyStore`, so no shipped code path can reach this store.
//
// Keys are non-permanent `SecKey`s built with `SecKeyCreateRandomKey` without
// a token id, and every operation uses the same Security framework calls as
// the enclave store (`.ecdsaSignatureDigestX962SHA256`, which emits DER, and
// `.ecdhKeyExchangeStandard`), so the adapter sees the same output shapes.

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

        func keepKeysOnDelete(_ keep: Bool) {
            deleteKeepsKey = keep
        }

        func create(tag: Data, policy: BiometricPolicy) throws -> Data {
            policies.append(policy)
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]
            ]
            var cfError: Unmanaged<CFError>?
            guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) else {
                throw PlatformError.custodyError("software P-256 key generation failed")
            }
            createCalls += 1
            keys[tag] = key
            return try SecureEnclaveP256KeyStore.uncompressedPublicKey(of: key)
        }

        private func key(_ tag: Data) throws -> SecKey {
            guard let key = keys[tag] else {
                throw PlatformError.keyNotFound(SecureEnclaveP256KeyStore.handle(of: tag))
            }
            return key
        }

        func publicKey(tag: Data) throws -> Data {
            try SecureEnclaveP256KeyStore.uncompressedPublicKey(of: key(tag))
        }

        func sign(tag: Data, digest: Data) throws -> Data {
            var cfError: Unmanaged<CFError>?
            guard let der = try SecKeyCreateSignature(
                key(tag), .ecdsaSignatureDigestX962SHA256, digest as CFData, &cfError
            ) else {
                throw SecureEnclaveP256KeyStore.operationError("software P-256 signing", tag: tag, cfError)
            }
            return der as Data
        }

        func agree(tag: Data, peer: Data) throws -> Data {
            agreeCalls += 1
            let peerKey = try SecureEnclaveP256KeyStore.peerKey(peer)
            var cfError: Unmanaged<CFError>?
            guard let secret = try SecKeyCopyKeyExchangeResult(
                key(tag), .ecdhKeyExchangeStandard, peerKey, [:] as CFDictionary, &cfError
            ) else {
                throw SecureEnclaveP256KeyStore.operationError("software P-256 ECDH", tag: tag, cfError)
            }
            return secret as Data
        }

        func delete(tag: Data) -> Bool {
            if deleteKeepsKey {
                return keys[tag] != nil
            }
            return keys.removeValue(forKey: tag) != nil
        }

        func contains(tag: Data) -> Bool {
            keys[tag] != nil
        }

        /// The number of keys the store holds.
        var count: Int {
            keys.count
        }
    }

#endif // os(iOS) || os(macOS)
