// Key custody conformance tests for the AppleKeyCustody adapter.
//
// These tests validate the `KeyCustodyProvider` contract using the real
// Apple Keychain backend. Each test creates keys with unique handles
// and cleans up after itself to prevent Keychain pollution.
//
// The pseudonym derivation known-answer test verifies cross-platform
// determinism with the canonical Rust reference implementation
// (`derive_pseudonym_keypair` in `scp-crypto/src/pseudonym.rs`), asserting
// the literal spec §25.19 vectors for both the static (v1) and rotatable (v2)
// derivations.
//
// ## Pseudonym derivation (spec §9.10.4.A, §9.10.4.1)
//
// The HMAC key is a private-derived `pseudonym_secret`, NEVER the public key
// (public-key keying would be a membership-enumeration oracle). For software
// custody, `pseudonym_secret = HKDF-SHA256(ed25519_private_seed,
// salt="scp-pseudonym-secret-v1")` until slice S12, which is cross-platform
// deterministic; for
// hardware custody (Secure Enclave) it is a device-local secret and the
// pseudonym is device-local by design. The earlier ADR-027 amendment proposing
// public-key keying was rejected.
//
// v1 (static):   seed = HMAC-SHA256(pseudonym_secret, contextId || "scp-pseudonym")
// v2 (rotatable): seed = HMAC-SHA256(pseudonym_secret,
//                          contextId || BE64(epoch) || "scp-pseudonym-v2")
// d = HKDF-Expand-SHA256(seed, "SCP-PSEUDONYM-P256-V1", 48) mod (n - 1) + 1;
// the pseudonym public key is the 33-byte compressed P-256 point d * G.
//
// See spec §9.10.4.A, §9.10.4.1, §25.19, ADR-025 (Apple Platform Adapter), and
// ADR-006 (KeyCustody trait).

#if os(iOS) || os(macOS)

    import CommonCrypto
    import CryptoKit
    import Foundation
    @testable import SCP
    import Testing

    // MARK: - AppleKeyCustody Tests

    struct AppleKeyCustodyTests {
        /// Shared custody instance using default Keychain (no access group).
        /// Suitable for unit tests and simulator.
        private let custody = AppleKeyCustody(accessGroup: nil)

        // MARK: - generateKeypair

        @Test("generateKeypair returns non-empty handle for Ed25519")
        func generateEd25519Keypair() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            #expect(!handle.isEmpty, "handle should be a non-empty UUID string")
            // Cleanup
            try await custody.destroyKey(handle)
        }

        @Test("generateKeypair returns non-empty handle for X25519")
        func generateX25519Keypair() async throws {
            let handle = try await custody.generateKeypair(keyType: "x25519")
            #expect(!handle.isEmpty, "handle should be a non-empty UUID string")
            // Cleanup
            try await custody.destroyKey(handle)
        }

        @Test("generateKeypair rejects unknown key type")
        func generateUnknownKeyType() async throws {
            await #expect(throws: PlatformError.self) {
                _ = try await custody.generateKeypair(keyType: "rsa-4096")
            }
        }

        // MARK: - sign

        @Test("sign with Ed25519 key produces 64-byte signature")
        func signEd25519() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            let data = Data("hello world".utf8)
            let signature = try await custody.sign(handle, data: data)
            #expect(signature.count == 64, "Ed25519 signature must be 64 bytes")
            // Cleanup
            try await custody.destroyKey(handle)
        }

        @Test("sign with X25519 key throws wrongKeyType")
        func signX25519Fails() async throws {
            let handle = try await custody.generateKeypair(keyType: "x25519")
            await #expect(throws: PlatformError.self) {
                _ = try await custody.sign(handle, data: Data("test".utf8))
            }
            // Cleanup
            try await custody.destroyKey(handle)
        }

        @Test("sign with destroyed key throws keyNotFound")
        func signDestroyedKey() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            try await custody.destroyKey(handle)
            await #expect(throws: PlatformError.self) {
                _ = try await custody.sign(handle, data: Data("test".utf8))
            }
        }

        @Test("Ed25519 signature verifies with CryptoKit")
        func signatureVerifies() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            let message = Data("important message".utf8)

            let signature = try await custody.sign(handle, data: message)
            let publicKeyBytes = try await custody.publicKey(handle)

            // Verify using CryptoKit
            let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyBytes)
            let isValid = publicKey.isValidSignature(signature, for: message)
            #expect(isValid, "signature must verify against the public key")

            // Cleanup
            try await custody.destroyKey(handle)
        }

        // MARK: - publicKey

        @Test("publicKey returns 32 bytes for Ed25519")
        func publicKeyEd25519() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            let pubKey = try await custody.publicKey(handle)
            #expect(pubKey.count == 32, "Ed25519 public key must be 32 bytes")
            // Cleanup
            try await custody.destroyKey(handle)
        }

        @Test("publicKey returns 32 bytes for X25519")
        func publicKeyX25519() async throws {
            let handle = try await custody.generateKeypair(keyType: "x25519")
            let pubKey = try await custody.publicKey(handle)
            #expect(pubKey.count == 32, "X25519 public key must be 32 bytes")
            // Cleanup
            try await custody.destroyKey(handle)
        }

        @Test("publicKey with destroyed handle throws keyNotFound")
        func publicKeyDestroyedHandle() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            try await custody.destroyKey(handle)
            await #expect(throws: PlatformError.self) {
                _ = try await custody.publicKey(handle)
            }
        }

        @Test("publicKey reads from metadata cache without accessing key material")
        func publicKeyFromMetadataCache() async throws {
            // Generate a key -- the public key should be cached in metadata.
            let handle = try await custody.generateKeypair(keyType: "ed25519")

            // Read the public key via the API.
            let pubKey = try await custody.publicKey(handle)
            #expect(pubKey.count == 32)

            // Verify the cached public key matches a fresh derivation from
            // the private key bytes (read directly from Keychain).
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "scp.key.\(handle)",
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne
            ]
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            #expect(status == errSecSuccess)
            if let privData = result as? Data {
                let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privData)
                #expect(
                    pubKey == signingKey.publicKey.rawRepresentation,
                    "cached public key must match derived public key"
                )
            }

            // Cleanup
            try await custody.destroyKey(handle)
        }

        // MARK: - destroyKey

        @Test("destroyKey returns attestation with softwareOnly method")
        func destroyKeyAttestation() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            let attestation = try await custody.destroyKey(handle)
            #expect(attestation.method == .softwareOnly)
            #expect(attestation.confirmed == true)
        }

        @Test("destroyKey makes subsequent operations fail")
        func destroyKeyMakesOperationsFail() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            try await custody.destroyKey(handle)

            // All operations should now fail
            await #expect(throws: PlatformError.self) {
                _ = try await custody.sign(handle, data: Data("test".utf8))
            }
            await #expect(throws: PlatformError.self) {
                _ = try await custody.publicKey(handle)
            }
            await #expect(throws: PlatformError.self) {
                _ = try await custody.destroyKey(handle)
            }
        }

        // MARK: - dhAgree

        @Test("dhAgree with X25519 keys produces matching shared secrets")
        func dhAgreeProducesMatchingSecrets() async throws {
            let aliceHandle = try await custody.generateKeypair(keyType: "x25519")
            let bobHandle = try await custody.generateKeypair(keyType: "x25519")

            let alicePub = try await custody.publicKey(aliceHandle)
            let bobPub = try await custody.publicKey(bobHandle)

            let secretAB = try await custody.dhAgree(aliceHandle, peerPublic: bobPub)
            let secretBA = try await custody.dhAgree(bobHandle, peerPublic: alicePub)

            #expect(secretAB.count == 32, "shared secret must be 32 bytes")
            #expect(secretAB == secretBA, "both sides must compute the same shared secret")

            // Cleanup
            try await custody.destroyKey(aliceHandle)
            try await custody.destroyKey(bobHandle)
        }

        @Test("dhAgree with Ed25519 key throws wrongKeyType")
        func dhAgreeEd25519Fails() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            let peer = Data(repeating: 0, count: 32)
            await #expect(throws: PlatformError.self) {
                _ = try await custody.dhAgree(handle, peerPublic: peer)
            }
            // Cleanup
            try await custody.destroyKey(handle)
        }

        // MARK: - derivePseudonym

        @Test("derivePseudonym is deterministic for same inputs")
        func derivePseudonymDeterministic() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            let contextId = Data("test-context".utf8)

            let first = try await custody.derivePseudonym(handle, contextId: contextId)
            let second = try await custody.derivePseudonym(handle, contextId: contextId)

            #expect(
                first.publicKey == second.publicKey,
                "same identity key + same context_id = same pseudonym public key"
            )

            // Cleanup
            try await custody.destroyKey(handle)
            try await custody.destroyKey(first.keyId)
            // second.keyId is deterministic and equals first.keyId, so already destroyed
        }

        @Test("derivePseudonym produces different keys for different contexts")
        func derivePseudonymDifferentContexts() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")

            let pseudoA = try await custody.derivePseudonym(handle, contextId: Data("context-a".utf8))
            let pseudoB = try await custody.derivePseudonym(handle, contextId: Data("context-b".utf8))

            #expect(
                pseudoA.publicKey != pseudoB.publicKey,
                "different contexts must produce different pseudonyms"
            )

            // Cleanup
            try await custody.destroyKey(handle)
            try await custody.destroyKey(pseudoA.keyId)
            try await custody.destroyKey(pseudoB.keyId)
        }

        @Test("derivePseudonym with X25519 key throws wrongKeyType")
        func derivePseudonymX25519Fails() async throws {
            let handle = try await custody.generateKeypair(keyType: "x25519")
            await #expect(throws: PlatformError.self) {
                _ = try await custody.derivePseudonym(handle, contextId: Data("ctx".utf8))
            }
            // Cleanup
            try await custody.destroyKey(handle)
        }

        @Test("derived pseudonym handle signs a digest with low-s P-256 ECDSA")
        func derivedPseudonymCanSign() async throws {
            let identityHandle = try await custody.generateKeypair(keyType: "ed25519")
            let pseudonym = try await custody.derivePseudonym(
                identityHandle, contextId: Data("context-1".utf8)
            )
            #expect(pseudonym.publicKey.count == 33)
            #expect(try await custody.publicKey(pseudonym.keyId) == pseudonym.publicKey)

            let publicKey = try P256.Signing.PublicKey(compressedRepresentation: pseudonym.publicKey)
            // (n - 1) / 2, the largest low-s value (§9.5.1).
            let halfOrderHex = Array("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")
            let halfOrder = Data(stride(from: 0, to: 64, by: 2).compactMap {
                UInt8(String(halfOrderHex[$0 ..< $0 + 2]), radix: 16)
            })
            #expect(halfOrder.count == 32)
            for index in 0 ..< 16 {
                let digest = SHA256.hash(data: Data("pseudonym message \(index)".utf8))
                let signature = try await custody.sign(pseudonym.keyId, data: Data(digest))
                #expect(signature.count == 64)
                let ecdsa = try P256.Signing.ECDSASignature(rawRepresentation: signature)
                #expect(publicKey.isValidSignature(ecdsa, for: digest), "signature must verify")
                #expect(
                    signature.suffix(32).lexicographicallyPrecedes(halfOrder)
                        || signature.suffix(32) == halfOrder,
                    "s must be in the low half"
                )
            }

            // A pseudonym key signs only a 32-byte digest.
            await #expect(throws: PlatformError.self) {
                _ = try await custody.sign(pseudonym.keyId, data: Data("12 bytes....".utf8))
            }

            // Cleanup
            try await custody.destroyKey(identityHandle)
            try await custody.destroyKey(pseudonym.keyId)
        }

        // MARK: - custodyType

        @Test("custodyType returns 'software' for all keys")
        func custodyTypeReturnsSoftware() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            #expect(
                custody.custodyType(handle) == "software",
                "Keychain-backed keys report CustodyType::Software"
            )
            // Cleanup
            try await custody.destroyKey(handle)
        }

        // MARK: - Unique handles

        @Test("each generateKeypair call returns a unique handle")
        func uniqueHandles() async throws {
            let handle1 = try await custody.generateKeypair(keyType: "ed25519")
            let handle2 = try await custody.generateKeypair(keyType: "x25519")
            let handle3 = try await custody.generateKeypair(keyType: "ed25519")

            #expect(handle1 != handle2)
            #expect(handle2 != handle3)
            #expect(handle1 != handle3)

            // Cleanup
            try await custody.destroyKey(handle1)
            try await custody.destroyKey(handle2)
            try await custody.destroyKey(handle3)
        }
    }

    // MARK: - Rotatable Pseudonym Tests

    /// Tests for the v2 (rotatable, epoch-bound) pseudonym derivation and the
    /// cross-platform §25.19 known-answer vectors covering both v1 and v2.
    struct AppleKeyCustodyRotatablePseudonymTests {
        /// Shared custody instance using default Keychain (no access group).
        private let custody = AppleKeyCustody(accessGroup: nil)

        @Test("deriveRotatablePseudonym is deterministic for same inputs")
        func deriveRotatablePseudonymDeterministic() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            let contextId = Data("test-context".utf8)

            let first = try await custody.deriveRotatablePseudonym(
                handle, contextId: contextId, pseudonymEpoch: 1
            )
            let second = try await custody.deriveRotatablePseudonym(
                handle, contextId: contextId, pseudonymEpoch: 1
            )

            #expect(
                first.publicKey == second.publicKey,
                "same identity key + same context_id + same epoch = same pseudonym public key"
            )

            // Cleanup
            try await custody.destroyKey(handle)
            try await custody.destroyKey(first.keyId)
            // second.keyId is deterministic and equals first.keyId, so already destroyed
        }

        @Test("deriveRotatablePseudonym produces different keys for different epochs")
        func deriveRotatablePseudonymDifferentEpochs() async throws {
            let handle = try await custody.generateKeypair(keyType: "ed25519")
            let contextId = Data("rotating-context".utf8)

            let epoch1 = try await custody.deriveRotatablePseudonym(
                handle, contextId: contextId, pseudonymEpoch: 1
            )
            let epoch2 = try await custody.deriveRotatablePseudonym(
                handle, contextId: contextId, pseudonymEpoch: 2
            )

            #expect(
                epoch1.publicKey != epoch2.publicKey,
                "different epochs must produce different pseudonyms"
            )
            #expect(
                epoch1.keyId != epoch2.keyId,
                "different epochs must occupy distinct Keychain handle slots"
            )

            // Cleanup
            try await custody.destroyKey(handle)
            try await custody.destroyKey(epoch1.keyId)
            try await custody.destroyKey(epoch2.keyId)
        }

        @Test("deriveRotatablePseudonym with X25519 key throws wrongKeyType")
        func deriveRotatablePseudonymX25519Fails() async throws {
            let handle = try await custody.generateKeypair(keyType: "x25519")
            await #expect(throws: PlatformError.self) {
                _ = try await custody.deriveRotatablePseudonym(
                    handle, contextId: Data("ctx".utf8), pseudonymEpoch: 1
                )
            }
            // Cleanup
            try await custody.destroyKey(handle)
        }

        /// One §25.19 pseudonym vector: identity seed, identity scalar (the ikm),
        /// and the v1 and v2 (epoch 1) points over "context-alpha".
        struct PseudonymVector {
            let seed: Data
            let scalar: String
            let staticPoint: String
            let rotatedPoint: String
        }

        /// §25.19 vectors 30 and 31. The identity seed maps to the ikm scalar via
        /// the §25.2 label "SCP-TEST-VECTOR-KEY-V1"; every hex value is copied
        /// verbatim from the spec.
        static let pseudonymVectors: [PseudonymVector] = [
            PseudonymVector(
                seed: Data(repeating: 0x01, count: 32),
                scalar: "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
                staticPoint: "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
                rotatedPoint: "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479"
            ),
            PseudonymVector(
                seed: Data([0x9D] + [UInt8](1 ... 31)),
                scalar: "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
                staticPoint: "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
                rotatedPoint: "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3"
            )
        ]

        /// Cross-platform known-answer test (KAT) for pseudonym derivation.
        ///
        /// Asserts the Swift `AppleKeyCustody` pseudonym derivations reproduce
        /// the canonical spec §25.19 vectors byte-for-byte, proving the Swift
        /// adapter is wire-compatible with the Rust `derive_pseudonym_keypair`
        /// reference (`scp-crypto/src/pseudonym.rs`) across all SDKs.
        ///
        /// Both vectors use `context_id = "context-alpha"` (ASCII). For each
        /// identity seed the test asserts:
        /// - v1 (`derivePseudonym`) public key equals the literal §25.19 hex.
        /// - v2 epoch 1 (`deriveRotatablePseudonym`) public key equals the
        ///   literal §25.19 hex.
        /// - v1 ≠ v2 (domain separation between `"scp-pseudonym"` and
        ///   `"scp-pseudonym-v2"`).
        @Test("pseudonym derivation matches §25.19 known-answer vectors")
        func pseudonymKnownAnswerVectors() async throws {
            let contextId = Data("context-alpha".utf8)

            for vector in Self.pseudonymVectors {
                let ikm = try hexToData(vector.scalar)
                let v1Expected = try hexToData(vector.staticPoint)
                let v2Expected = try hexToData(vector.rotatedPoint)
                #expect(
                    P256Pseudonym.seedToScalar(label: "SCP-TEST-VECTOR-KEY-V1", seed: vector.seed)
                        == ikm,
                    "seed-to-scalar must reproduce the §25.19 identity scalar"
                )

                // Store the ikm as the Ed25519 identity seed the derivation reads.
                let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: ikm)
                let handle = UUID().uuidString
                try custody.storePrivateKeyBytes(
                    ikm, for: handle, keyType: .ed25519,
                    publicKeyBytes: signingKey.publicKey.rawRepresentation
                )

                // v1 (static) pseudonym.
                let staticPseudonym = try await custody.derivePseudonym(handle, contextId: contextId)
                #expect(
                    staticPseudonym.publicKey == v1Expected,
                    "v1 pseudonym public key must match the §25.19 KAT vector"
                )

                // v2 (rotatable) pseudonym at epoch 1.
                let rotatablePseudonym = try await custody.deriveRotatablePseudonym(
                    handle, contextId: contextId, pseudonymEpoch: 1
                )
                #expect(
                    rotatablePseudonym.publicKey == v2Expected,
                    "v2 (epoch=1) pseudonym public key must match the §25.19 KAT vector"
                )

                // Domain separation: v1 and v2 must differ.
                #expect(
                    staticPseudonym.publicKey != rotatablePseudonym.publicKey,
                    "v1 and v2 derivations must differ (domain separation)"
                )

                // Cleanup
                try await custody.destroyKey(handle)
                try await custody.destroyKey(staticPseudonym.keyId)
                try await custody.destroyKey(rotatablePseudonym.keyId)
            }
        }

        // MARK: - Helpers

        /// Decodes an even-length lowercase hex string into raw bytes.
        ///
        /// Used to load the literal §25.19 known-answer vectors without any
        /// self-derivation, so a regression in the derivation cannot mask itself.
        private func hexToData(_ hex: String) throws -> Data {
            guard hex.count % 2 == 0 else {
                throw PlatformError.custodyError("hex string must have even length")
            }
            var data = Data(capacity: hex.count / 2)
            var index = hex.startIndex
            while index < hex.endIndex {
                let next = hex.index(index, offsetBy: 2)
                guard let byte = UInt8(hex[index ..< next], radix: 16) else {
                    throw PlatformError.custodyError("invalid hex byte in '\(hex)'")
                }
                data.append(byte)
                index = next
            }
            return data
        }
    }

    // MARK: - BiometricPolicy Tests

    struct AppleKeyCustodyBiometricPolicyTests {
        // MARK: - Default behavior preserved

        @Test("BiometricPolicy.none preserves existing behavior")
        func biometricNoneMatchesCurrentBehavior() async throws {
            let custodyDefault = AppleKeyCustody(accessGroup: nil)
            let custodyExplicit = AppleKeyCustody(accessGroup: nil, biometricPolicy: .none)

            // Both should generate keys identically.
            let handle1 = try await custodyDefault.generateKeypair(keyType: "ed25519")
            let handle2 = try await custodyExplicit.generateKeypair(keyType: "ed25519")

            // Both should sign successfully.
            let data = Data("test".utf8)
            let sig1 = try await custodyDefault.sign(handle1, data: data)
            let sig2 = try await custodyExplicit.sign(handle2, data: data)

            #expect(sig1.count == 64)
            #expect(sig2.count == 64)

            // Cleanup
            try await custodyDefault.destroyKey(handle1)
            try await custodyExplicit.destroyKey(handle2)
        }

        // MARK: - custodyType reflects biometric policy

        @Test("custodyType returns 'software' for BiometricPolicy.none")
        func custodyTypeNone() async throws {
            let custodyNone = AppleKeyCustody(accessGroup: nil, biometricPolicy: .none)
            let handle = try await custodyNone.generateKeypair(keyType: "ed25519")
            #expect(custodyNone.custodyType(handle) == "software")
            try await custodyNone.destroyKey(handle)
        }

        @Test("custodyType returns 'software_biometric' for BiometricPolicy.required")
        func custodyTypeRequired() {
            let custodyBio = AppleKeyCustody(accessGroup: nil, biometricPolicy: .required)
            // custodyType does not access the Keychain -- it reflects the policy.
            #expect(custodyBio.custodyType("any-handle") == "software_biometric")
        }

        // MARK: - BiometricPolicy.required creates biometric-gated keys

        /// Whether the Keychain supports biometric-protected items in this
        /// environment. CLI test runners and CI lack the entitlement
        /// (`errSecMissingEntitlement` / `-34018`).
        private static var biometricKeychainAvailable: Bool = {
            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .biometryCurrentSet, nil
            ) else { return false }
            let tag = "scp.test.biometric-probe"
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: tag,
                kSecValueData as String: Data([0x42]),
                kSecAttrAccessControl as String: access
            ]
            let status = SecItemAdd(query as CFDictionary, nil)
            if status == errSecSuccess {
                SecItemDelete(
                    [kSecClass as String: kSecClassGenericPassword,
                     kSecAttrAccount as String: tag] as CFDictionary
                )
                return true
            }
            // -34018 = errSecMissingEntitlement
            return status != -34018
        }()

        /// Verifies that a key stored with `.required` biometric policy uses
        /// `SecAccessControl` with `.biometryCurrentSet`.
        ///
        /// Note: On simulator without enrolled biometrics, the key creation
        /// succeeds but biometric-gated access will fall back to passcode.
        /// Full biometric prompt testing requires a device with enrolled
        /// biometrics -- see ADR-025 Biometric gating for manual testing steps.
        @Test(
            "BiometricPolicy.required stores key with biometric access control",
            .enabled(if: biometricKeychainAvailable, "Requires Keychain biometric entitlements")
        )
        func biometricRequiredStoresWithAccessControl() async throws {
            let custodyBio = AppleKeyCustody(accessGroup: nil, biometricPolicy: .required)
            let handle = try await custodyBio.generateKeypair(keyType: "ed25519")

            // Verify the key exists and has an access control attribute by
            // querying the Keychain for attributes.
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "scp.key.\(handle)",
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne
            ]
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            #expect(status == errSecSuccess, "key should exist in Keychain")

            if let attrs = result as? [String: Any] {
                // When SecAccessControl is set, kSecAttrAccessControl is present
                // in the returned attributes and kSecAttrAccessible is NOT set
                // (they are mutually exclusive in the Keychain).
                let hasAccessControl = attrs[kSecAttrAccessControl as String] != nil
                #expect(
                    hasAccessControl,
                    "biometric key must have kSecAttrAccessControl set"
                )
            }

            // Cleanup
            try await custodyBio.destroyKey(handle)
        }

        // MARK: - BiometricPolicy enum equality

        @Test("BiometricPolicy raw values")
        func biometricPolicyRawValues() {
            #expect(BiometricPolicy.none.rawValue == "none")
            #expect(BiometricPolicy.required.rawValue == "required")
            #expect(BiometricPolicy.none != BiometricPolicy.required)
        }

        // MARK: - biometricPolicy property is accessible

        @Test("biometricPolicy is stored and accessible")
        func biometricPolicyStored() {
            let custodyNone = AppleKeyCustody(accessGroup: nil, biometricPolicy: .none)
            let custodyReq = AppleKeyCustody(accessGroup: nil, biometricPolicy: .required)
            #expect(custodyNone.biometricPolicy == .none)
            #expect(custodyReq.biometricPolicy == .required)
        }
    }

#endif // os(iOS) || os(macOS)
