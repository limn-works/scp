// Key custody conformance tests for the AppleKeyCustody adapter.
//
// These tests validate the `KeyCustodyProvider` contract using the real
// Apple Keychain backend. Each test creates keys with unique handles
// and cleans up after itself to prevent Keychain pollution.
//
// The pseudonym derivation golden vector test verifies cross-platform
// determinism with the canonical Rust reference implementation
// (`InMemoryKeyCustody` in `scp-platform/src/testing/key_custody.rs`).
//
// ## ADR-027 Amendment
//
// Pseudonym derivation uses Ed25519 **public** key bytes as the HMAC key,
// not private key bytes. This ensures cross-platform determinism with
// hardware TEE adapters (e.g., Android Keystore) that cannot export
// private key material.
//
// See ADR-025 (Apple Platform Adapter) and ADR-006 (KeyCustody trait).

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

        /// Cross-platform golden-value test for pseudonym derivation.
        ///
        /// Verifies that the Swift `AppleKeyCustody.derivePseudonym` produces
        /// the same pseudonym public key as the Rust `InMemoryKeyCustody`
        /// reference implementation for the same inputs.
        ///
        /// The golden vector uses:
        /// - Identity key seed: 0x00...01 (31 zeros, then 0x01)
        /// - Context ID: "test" (4 bytes UTF-8)
        /// - Algorithm: `HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym")`
        ///
        /// This test imports a known private key into the Keychain, derives the
        /// pseudonym, and compares the result against the reference algorithm
        /// computed locally.
        @Test("derivePseudonym cross-platform golden vector (ADR-027)")
        func derivePseudonymGoldenVector() async throws {
            // Known identity key seed: 0x00...01 (31 zeros, then 0x01).
            var seedBytes = Data(repeating: 0, count: 32)
            seedBytes[31] = 1
            let contextId = Data("test".utf8)

            // Derive the public key from the seed for metadata caching.
            let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedBytes)
            let publicKeyBytes = signingKey.publicKey.rawRepresentation

            // Store the known seed as an Ed25519 private key in Keychain.
            let handle = UUID().uuidString
            try custody.storePrivateKeyBytes(
                seedBytes, for: handle, keyType: .ed25519, publicKeyBytes: publicKeyBytes
            )

            // Compute expected pseudonym using the reference algorithm directly:
            // seed = HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym")
            let hmacKey = SymmetricKey(data: publicKeyBytes)
            var hmac = CryptoKit.HMAC<SHA256>(key: hmacKey)
            hmac.update(data: contextId)
            hmac.update(data: Data("scp-pseudonym".utf8))
            let expectedSeed = Data(hmac.finalize())

            let expectedKey = try Curve25519.Signing.PrivateKey(rawRepresentation: expectedSeed.prefix(32))
            let expectedPublicKey = expectedKey.publicKey.rawRepresentation

            // Derive pseudonym through AppleKeyCustody
            let pseudonym = try await custody.derivePseudonym(handle, contextId: contextId)

            #expect(
                pseudonym.publicKey == expectedPublicKey,
                "pseudonym public key must match reference HMAC-SHA256 algorithm output"
            )

            // Cleanup
            try await custody.destroyKey(handle)
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

        /// Verifies that a key stored with `.required` biometric policy uses
        /// `SecAccessControl` with `.biometryCurrentSet`.
        ///
        /// Note: On simulator without enrolled biometrics, the key creation
        /// succeeds but biometric-gated access will fall back to passcode.
        /// Full biometric prompt testing requires a device with enrolled
        /// biometrics -- see ADR-025 Biometric gating for manual testing steps.
        @Test("BiometricPolicy.required stores key with biometric access control")
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
