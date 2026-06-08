// Key custody conformance tests for the AppleKeyCustody adapter.
//
// These tests validate the `KeyCustodyProvider` contract using the real
// Apple Keychain backend. Each test creates keys with unique handles
// and cleans up after itself to prevent Keychain pollution.
//
// The pseudonym derivation known-answer test verifies cross-platform
// determinism with the canonical Rust reference implementation
// (`derive_pseudonym_keypair` in `scp-platform/src/pseudonym.rs`), asserting
// the literal spec §25.19 vectors for both the static (v1) and rotatable (v2)
// derivations.
//
// ## Pseudonym derivation (spec §9.10.4.A, §9.10.4.1)
//
// The HMAC key is a private-derived `pseudonym_secret`, NEVER the public key
// (public-key keying would be a membership-enumeration oracle). For software
// custody, `pseudonym_secret = HKDF-SHA256(ed25519_private_seed,
// salt="scp-pseudonym-secret-v1")`, which is cross-platform deterministic; for
// hardware custody (Secure Enclave) it is a device-local secret and the
// pseudonym is device-local by design. The earlier ADR-027 amendment proposing
// public-key keying was rejected.
//
// v1 (static):   seed = HMAC-SHA256(pseudonym_secret, contextId || "scp-pseudonym")
// v2 (rotatable): seed = HMAC-SHA256(pseudonym_secret,
//                          contextId || BE64(epoch) || "scp-pseudonym-v2")
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
            try await custody.destroyKey(first.handle)
            // second.handle is deterministic and equals first.handle, so already destroyed
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
            try await custody.destroyKey(pseudoA.handle)
            try await custody.destroyKey(pseudoB.handle)
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

        @Test("derived pseudonym handle can sign and verify")
        func derivedPseudonymCanSign() async throws {
            let identityHandle = try await custody.generateKeypair(keyType: "ed25519")
            let pseudonym = try await custody.derivePseudonym(
                identityHandle, contextId: Data("context-1".utf8)
            )

            let message = Data("pseudonym signed message".utf8)
            let signature = try await custody.sign(pseudonym.handle, data: message)

            // Verify
            let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: pseudonym.publicKey)
            let isValid = publicKey.isValidSignature(signature, for: message)
            #expect(isValid, "pseudonym signature must verify against pseudonym public key")

            // Cleanup
            try await custody.destroyKey(identityHandle)
            try await custody.destroyKey(pseudonym.handle)
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
            try await custody.destroyKey(first.handle)
            // second.handle is deterministic and equals first.handle, so already destroyed
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
                epoch1.handle != epoch2.handle,
                "different epochs must occupy distinct Keychain handle slots"
            )

            // Cleanup
            try await custody.destroyKey(handle)
            try await custody.destroyKey(epoch1.handle)
            try await custody.destroyKey(epoch2.handle)
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

        /// Cross-platform known-answer test (KAT) for pseudonym derivation.
        ///
        /// Asserts the Swift `AppleKeyCustody` pseudonym derivations reproduce
        /// the canonical spec §25.19 vectors byte-for-byte, proving the Swift
        /// adapter is wire-compatible with the Rust `derive_pseudonym_keypair`
        /// reference (`scp-platform/src/pseudonym.rs`) across all SDKs.
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

            // §25.19 V30: identity seed = 0x01 repeated 32 times.
            let seedV30 = Data(repeating: 0x01, count: 32)
            let v1ExpectedV30 = try hexToData(
                "fddc04882a48aa39888f6dbec622f9c5aa6f06b2e40820a69a2e0e89b5f09ac2"
            )
            let v2ExpectedV30 = try hexToData(
                "43e50a947c4b2be44f871e309c7edc64afaf4207b9a589c9b01f61c01158090f"
            )

            // §25.19 V31: identity seed = 0x9D, then 0x01, 0x02, ..., 0x1F.
            var seedV31 = Data([0x9D])
            seedV31.append(contentsOf: [UInt8](1 ... 31))
            let v1ExpectedV31 = try hexToData(
                "ff6e2e909a008318f97bb2c26c1d787ceb9aa2996f746766335e10ba7e2213cc"
            )
            let v2ExpectedV31 = try hexToData(
                "edd47319719e2350d1db9488e0189f2405267d7dc243489cfd9aa6f3ac3fc639"
            )

            for (seedBytes, v1Expected, v2Expected) in [
                (seedV30, v1ExpectedV30, v2ExpectedV30),
                (seedV31, v1ExpectedV31, v2ExpectedV31)
            ] {
                #expect(seedBytes.count == 32, "identity seed must be 32 bytes")

                // Derive the public key from the seed for metadata caching.
                let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedBytes)
                let publicKeyBytes = signingKey.publicKey.rawRepresentation

                // Store the known seed as an Ed25519 identity key in Keychain.
                let handle = UUID().uuidString
                try custody.storePrivateKeyBytes(
                    seedBytes, for: handle, keyType: .ed25519, publicKeyBytes: publicKeyBytes
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
                try await custody.destroyKey(staticPseudonym.handle)
                try await custody.destroyKey(rotatablePseudonym.handle)
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
