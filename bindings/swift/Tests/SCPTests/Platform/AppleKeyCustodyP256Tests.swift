// P-256 and HPKE P-256 custody tests for `AppleKeyCustody` (ADR-025
// criteria 1, 7, 8 and 9; spec 09 §9.5; spec 03 §3.7.2).
//
// Every test but the two production-store tests runs the adapter over
// `SoftwareP256KeyStore`, the test-only store, because a `swift test` host
// holds no Secure Enclave key it can generate under an app entitlement. Each
// result is checked against a Rust oracle the `testing` build exports
// (`testingP256VerifyStrict`, `testingP256Ecdh`) or through the bridge's own
// custody object (`TestingCallbackCustody`), never against CryptoKit run on
// the same key.
//
// The suite is serialized: the fail-closed test counts the P-256 items in
// the Keychain before and after, and no other test in this suite may add one
// meanwhile.

#if os(iOS) || os(macOS)

    import CryptoKit
    import Foundation
    @testable import SCP
    import Security
    import Testing

    /// Whether the production Secure Enclave store can create a key here: a
    /// create-and-delete probe through `SecureEnclaveP256KeyStore` itself. An
    /// unsigned `swift test` binary gets `errSecMissingEntitlement` even on a
    /// Mac with an enclave, so `SecureEnclave.isAvailable` is not the
    /// predicate.
    /// Whether this process can mint a Secure Enclave key. The probe calls
    /// the Security framework directly, never ``SecureEnclaveP256KeyStore``,
    /// so a store that fell back to a software key could not flip it and
    /// skip the fail-closed test.
    let secureEnclaveAvailable: Bool = {
        let tag = Data("scp.key.enclave-probe-\(UInt64.random(in: .min ... .max))".utf8)
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag
            ]
        ]
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        #if os(macOS)
            attributes[kSecUseDataProtectionKeychain as String] = true
            query[kSecUseDataProtectionKeychain as String] = true
        #endif
        guard SecKeyCreateRandomKey(attributes as CFDictionary, nil) != nil else { return false }
        SecItemDelete(query as CFDictionary)
        return true
    }()

    /// Fixtures shared by the P-256 custody tests.
    enum P256Fixture {
        /// The upper bound of a low `s`: `⌊n / 2⌋` of the P-256 group order.
        static let halfOrder: [UInt8] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8
        ]

        static func isLowS(_ signature: Data) -> Bool {
            let sValue = [UInt8](signature.suffix(32))
            return sValue.lexicographicallyPrecedes(halfOrder) || sValue == halfOrder
        }

        static func randomDigest() -> Data {
            Data((0 ..< 32).map { _ in UInt8.random(in: .min ... .max) })
        }

        static func adapter(
            _ store: SoftwareP256KeyStore,
            policy: BiometricPolicy = .none
        ) -> AppleKeyCustody {
            AppleKeyCustody(accessGroup: nil, biometricPolicy: policy, p256Store: store)
        }

        /// Runs `body` and returns the code of the `ScpError.Crypto` it threw,
        /// or a description of whatever else happened.
        static func cryptoCode(_ body: () async throws -> Void) async -> String {
            do {
                try await body()
                return "no error"
            } catch let ScpError.Crypto(_, code) {
                return code
            } catch {
                return "other error: \(error)"
            }
        }

        /// The P-256 items in the Keychain: companion generic-password items
        /// whose label records a P-256 type, and key items whose tag carries
        /// the adapter's prefix, in either keychain on macOS. A query the
        /// process may not run (no entitlement) holds nothing it could add.
        static func p256ItemCount() -> Int {
            var count = 0
            var companions: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll
            ]
            var result: AnyObject?
            if SecItemCopyMatching(companions as CFDictionary, &result) == errSecSuccess,
               let items = result as? [[String: Any]] {
                count += items.filter { attrs in
                    guard
                        let account = attrs[kSecAttrAccount as String] as? String,
                        account.hasPrefix("scp.key."),
                        let label = attrs[kSecAttrLabel as String] as? String
                    else { return false }
                    return label.contains("\"keyType\":\"p256\"") || label.contains("\"keyType\":\"hpke-p256\"")
                }.count
            }
            companions.removeAll()
            for dataProtection in [false, true] {
                var keys: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecReturnAttributes as String: true,
                    kSecMatchLimit as String: kSecMatchLimitAll
                ]
                #if os(macOS)
                    if dataProtection {
                        keys[kSecUseDataProtectionKeychain as String] = true
                    }
                #else
                    if dataProtection {
                        continue
                    }
                #endif
                var keyResult: AnyObject?
                if SecItemCopyMatching(keys as CFDictionary, &keyResult) == errSecSuccess,
                   let items = keyResult as? [[String: Any]] {
                    count += items.filter { attrs in
                        guard let tag = attrs[kSecAttrApplicationTag as String] as? Data else { return false }
                        return tag.starts(with: Data("scp.key.".utf8))
                    }.count
                }
            }
            return count
        }
    }

    @Suite(.serialized)
    struct AppleKeyCustodyP256Tests {
        // MARK: - Signing

        /// Sign succeeds through the bridge: the bridge's custody object
        /// signs a 32-byte digest with the adapter's P-256 key and the strict
        /// Rust verifier accepts the 64 bytes under the 33-byte public key.
        /// The bridge verifies every host signature, so this proves the
        /// digest is signed as given (no second hash) under the reported key;
        /// it cannot observe the form the host emitted, which the next test
        /// checks.
        @Test("a P-256 key signs through the bridge and the strict verifier accepts it")
        func p256SignSucceedsThroughTheBridge() async throws {
            let store = SoftwareP256KeyStore()
            let bridge = TestingCallbackCustody(provider: P256Fixture.adapter(store))
            let keyId = try await bridge.generateKeypair(keyType: .p256)
            let publicKey = try await bridge.publicKey(keyId: keyId)
            #expect(publicKey.count == 33)
            for _ in 0 ..< 8 {
                let digest = P256Fixture.randomDigest()
                let signature = try await bridge.sign(keyId: keyId, data: digest)
                #expect(signature.count == 64)
                #expect(try testingP256VerifyStrict(publicKey: publicKey, digest: digest, signature: signature))
            }
            try await bridge.destroyKey(keyId: keyId)
        }

        /// ADR-025 criterion 1 at the host: `sign` returns the raw 64-byte
        /// `r || s` with `s` low. Half of all ECDSA signatures have a high
        /// `s`, so 32 signatures all low is chance with probability 2^-32
        /// unless the adapter normalizes.
        @Test("AppleKeyCustody.sign returns a 64-byte raw signature with a low s")
        func hostSignReturnsRawLowS() async throws {
            let store = SoftwareP256KeyStore()
            let custody = P256Fixture.adapter(store)
            let keyId = try await custody.generateKeypair(keyType: "p256")
            let publicKey = try await custody.publicKey(keyId)
            for _ in 0 ..< 32 {
                let digest = P256Fixture.randomDigest()
                let signature = try await custody.sign(keyId, data: digest)
                #expect(signature.count == 64, "sign must return raw r || s, not DER")
                #expect(P256Fixture.isLowS(signature), "s must be in the low half of the group order")
                #expect(try testingP256VerifyStrict(publicKey: publicKey, digest: digest, signature: signature))
            }
            try await custody.destroyKey(keyId)
        }

        // MARK: - Agreement

        /// The bridge's `dhAgree` over the adapter's HPKE key equals the Rust
        /// ECDH oracle run from the peer's side.
        @Test("an HPKE P-256 key agrees through the bridge to the Rust ECDH oracle's secret")
        func hpkeAgreementMatchesTheOracle() async throws {
            let store = SoftwareP256KeyStore()
            let bridge = TestingCallbackCustody(provider: P256Fixture.adapter(store))
            let keyId = try await bridge.generateKeypair(keyType: .hpkeP256)
            let hostPublic = try await bridge.publicKey(keyId: keyId)
            #expect(hostPublic.count == 65)
            let peer = P256.KeyAgreement.PrivateKey()
            let shared = try await bridge.dhAgree(keyId: keyId, peerPublic: peer.publicKey.x963Representation)
            let expected = try testingP256Ecdh(peerScalar: peer.rawRepresentation, hostPublic: hostPublic)
            #expect(shared.count == 32)
            #expect(shared == expected)
            try await bridge.destroyKey(keyId: keyId)
        }

        /// A peer point off the curve is refused by the adapter itself before
        /// the store's agreement runs. The bridge filters such a point first,
        /// so only a host-level call shows the adapter's own check.
        @Test("dhAgree refuses an off-curve peer before the agreement runs")
        func offCurvePeerIsRefusedBeforeAgreement() async throws {
            let store = SoftwareP256KeyStore()
            let custody = P256Fixture.adapter(store)
            let keyId = try await custody.generateKeypair(keyType: "hpke-p256")
            var offCurve = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
            offCurve[64] ^= 0x01
            await #expect(throws: PlatformError.self) {
                _ = try await custody.dhAgree(keyId, peerPublic: offCurve)
            }
            #expect(await store.agreeCalls == 0)
            try await custody.destroyKey(keyId)
        }

        // MARK: - Type separation and reporting

        @Test("a P-256 key refuses dhAgree and an HPKE P-256 key refuses sign, as SCP-CRYPTO-4060")
        func wrongTypeOperationsAreRefused() async throws {
            let store = SoftwareP256KeyStore()
            let provider: any KeyCustodyProvider = P256Fixture.adapter(store)
            let signing = try await provider.generateKeypair(keyType: .p256, role: .operational)
            let wrapping = try await provider.generateKeypair(keyType: .hpkeP256, role: .operational)
            let peer = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
            #expect(await P256Fixture.cryptoCode {
                _ = try await provider.dhAgree(keyId: signing, peerPublic: peer)
            } == "SCP-CRYPTO-4060")
            #expect(await P256Fixture.cryptoCode {
                _ = try await provider.sign(keyId: wrapping, message: P256Fixture.randomDigest())
            } == "SCP-CRYPTO-4060")
            #expect(await store.agreeCalls == 0)
            try await provider.destroyKey(keyId: signing)
            try await provider.destroyKey(keyId: wrapping)
        }

        @Test("getPublicKey reports P-256 as 33 bytes and HPKE P-256 as 65 bytes, each with its role")
        func getPublicKeyReportsTypeLengthAndRole() async throws {
            let store = SoftwareP256KeyStore()
            let provider: any KeyCustodyProvider = P256Fixture.adapter(store)
            let signing = try await provider.generateKeypair(keyType: .p256, role: .identity)
            let wrapping = try await provider.generateKeypair(keyType: .hpkeP256, role: .operational)

            let signingKey = try await provider.getPublicKey(keyId: signing)
            #expect(signingKey.keyType == .p256)
            #expect(signingKey.role == .identity)
            #expect(signingKey.publicKey.count == 33)
            #expect(signingKey.publicKey.first == 0x02 || signingKey.publicKey.first == 0x03)

            let wrappingKey = try await provider.getPublicKey(keyId: wrapping)
            #expect(wrappingKey.keyType == .hpkeP256)
            #expect(wrappingKey.role == .operational)
            #expect(wrappingKey.publicKey.count == 65)
            #expect(wrappingKey.publicKey.first == 0x04)

            try await provider.destroyKey(keyId: signing)
            try await provider.destroyKey(keyId: wrapping)
        }

        /// The bridge's own mapping reads the adapter's string: an enclave
        /// key must reach Rust as hardware custody, not the in-memory
        /// fallback an unrecognised string gets.
        @Test("the bridge sees an enclave key as hardware custody")
        func bridgeSeesHardwareCustody() async throws {
            let store = SoftwareP256KeyStore()
            let custody = P256Fixture.adapter(store, policy: .required)
            let bridge = TestingCallbackCustody(provider: custody)
            for keyType in [CustodyKeyType.p256, .hpkeP256] {
                let keyId = try await bridge.generateKeypair(keyType: keyType)
                #expect(custody.custodyType(keyId: keyId) == "hardware")
                #expect(try bridge.custodyType(keyId: keyId) == "hardware")
                try await bridge.destroyKey(keyId: keyId)
            }
        }

        /// An identity under `.required` applies the policy to every key it
        /// creates, the HPKE wrapping key included.
        @Test("the biometric policy reaches the store for both P-256 key types")
        func biometricPolicyReachesTheStore() async throws {
            let store = SoftwareP256KeyStore()
            let custody = P256Fixture.adapter(store, policy: .required)
            let signing = try await custody.generateKeypair(keyType: "p256")
            let wrapping = try await custody.generateKeypair(keyType: "hpke-p256")
            #expect(await store.policies == [.required, .required])
            try await custody.destroyKey(signing)
            try await custody.destroyKey(wrapping)
        }

        // MARK: - Destruction and persistence

        /// Destruction is confirmed by re-fetching the key, not by the
        /// store's own report: a delete that reports success but leaves the
        /// key is `destructionFailed`, and the record of the key survives.
        @Test("destroyKey re-fetches the enclave key and refuses to confirm one that survived deletion")
        func destroyConfirmsByRefetch() async throws {
            let store = SoftwareP256KeyStore()
            let custody = P256Fixture.adapter(store)
            let keyId = try await custody.generateKeypair(keyType: "hpke-p256")
            await store.keepKeysOnDelete(true)
            do {
                _ = try await custody.destroyKey(keyId)
                Issue.record("destroyKey confirmed a key the store still holds")
            } catch let error as PlatformError {
                guard case .destructionFailed = error else {
                    Issue.record("expected destructionFailed, got \(error)")
                    return
                }
            }
            #expect(await store.count == 1)
            #expect(custody.custodyType(keyId) == "hardware", "the record of a surviving key must remain")
            await store.keepKeysOnDelete(false)
            try await custody.destroyKey(keyId)
        }

        @Test("a destroyed P-256 key is gone from the store and reports SCP-CRYPTO-4006")
        func destroyedKeyIsGone() async throws {
            let store = SoftwareP256KeyStore()
            let custody = P256Fixture.adapter(store)
            let provider: any KeyCustodyProvider = custody
            for keyType in [CustodyKeyType.p256, .hpkeP256] {
                let keyId = try await provider.generateKeypair(keyType: keyType, role: .operational)
                #expect(await store.count == 1)
                let attestation = try await custody.destroyKey(keyId)
                #expect(attestation.confirmed)
                #expect(attestation.method == .softwareOnly)
                #expect(await store.count == 0)
                #expect(await P256Fixture.cryptoCode { _ = try await provider.getPublicKey(keyId: keyId) } == "SCP-CRYPTO-4006")
                #expect(await P256Fixture.cryptoCode { try await provider.destroyKey(keyId: keyId) } == "SCP-CRYPTO-4006")
                #expect(provider.custodyType(keyId: keyId) == "in_memory")
            }
        }

        /// A new adapter over the same store (an app restart) finds the key:
        /// the companion item keeps its type, role and public key, and the
        /// store keeps the private key.
        @Test("an HPKE P-256 key survives a new adapter over the same store")
        func hpkeKeySurvivesARestart() async throws {
            let store = SoftwareP256KeyStore()
            let first: any KeyCustodyProvider = P256Fixture.adapter(store)
            let keyId = try await first.generateKeypair(keyType: .hpkeP256, role: .identity)
            let before = try await first.getPublicKey(keyId: keyId)

            let second: any KeyCustodyProvider = P256Fixture.adapter(store)
            let after = try await second.getPublicKey(keyId: keyId)
            #expect(after.publicKey == before.publicKey)
            #expect(after.publicKey.count == 65)
            #expect(after.keyType == .hpkeP256)
            #expect(after.role == .identity)

            let peer = P256.KeyAgreement.PrivateKey()
            let shared = try await second.dhAgree(keyId: keyId, peerPublic: peer.publicKey.x963Representation)
            #expect(try shared == testingP256Ecdh(peerScalar: peer.rawRepresentation, hostPublic: after.publicKey))
            try await second.destroyKey(keyId: keyId)
        }

        // MARK: - End to end

        /// The joiner's identity lives in the adapter; `reserveKeyPackage`
        /// mints its HPKE P-256 wrapping key there, the creator seals the
        /// invitation to it, and the join opens the seal through the
        /// adapter's `dhAgree`.
        @Test("a joiner whose custody is the adapter opens a sealed invitation")
        func joinerOpensASealedInvitation() async throws {
            let store = SoftwareP256KeyStore()
            let custody = P256Fixture.adapter(store)
            let creatorScp = try SCP(storage: .inMemory)
            let joinerScp = try SCP(storage: .inMemory)

            let creator = try await createInMemoryIdentity(creatorScp)
            // The two instances resolve each other's DIDs, as two processes
            // sharing the Mainline DHT do.
            try testingShareDidResolver(source: creatorScp.inner, target: joinerScp.inner)
            let joiner = try await joinerScp.identityCreateWithCustody(provider: custody)
            let reservation = try await joinerScp.reserveKeyPackage(identity: joiner)

            let context = try await creatorScp.contextCreate(identity: creator, params: ContextParams(
                mode: .encrypted,
                ceiling: ["messages:read", "messages:write", "member:invite", "governance:propose"],
                ceilingPolicy: .immutable,
                governance: .singleAdmin,
                memoryScope: .ephemeral,
                ttlSeconds: 3600,
                promotable: false,
                minProtocolVersion: 0,
                maxChainDepth: nil,
                maxNestingDepth: nil,
                sessionCap: nil,
                economicPolicy: nil,
                consequenceRulesJson: nil,
                consequenceConfigJson: nil,
                capabilityRequirementsJson: nil,
                pseudonymRotation: nil
            ))
            let outcome = try await creatorScp.inviteMember(
                identity: creator,
                contextId: context.contextId(),
                inviteeDid: joiner.did(),
                inviteeKeyPackage: reservation.keyPackagePublic
            )
            guard case let .sealed(bundle, _) = outcome else {
                Issue.record("inviteMember did not seal: \(outcome)")
                return
            }
            let joined = try await joinerScp.contextJoinFromWelcome(
                identity: joiner,
                sealed: bundle,
                reservationId: reservation.reservationId
            )
            #expect(joined.contextId() == context.contextId())
            #expect(await store.agreeCalls >= 1, "the join must open the seal through the adapter")

            try await creatorScp.shutdown(timeoutMillis: 1000)
            try await joinerScp.shutdown(timeoutMillis: 1000)
        }

        // MARK: - Production store

        /// ADR-025 criterion 8 where no enclave is reachable: the SDK's own
        /// `AppleKeyCustody()` throws the typed error for both P-256 types,
        /// the bridge sees `SCP-CRYPTO-4060`, and no item of either class is
        /// left behind, so nothing fell back to a software key.
        @Test(
            "without a Secure Enclave, P-256 generation fails closed and leaves no item",
            .enabled(if: !secureEnclaveAvailable)
        )
        func productionStoreFailsClosedWithoutAnEnclave() async throws {
            let custody = AppleKeyCustody()
            let provider: any KeyCustodyProvider = custody
            let before = P256Fixture.p256ItemCount()
            for keyType in ["p256", "hpke-p256"] {
                do {
                    let keyId = try await custody.generateKeypair(keyType: keyType)
                    Issue.record("generateKeypair(\(keyType)) returned \(keyId) without an enclave")
                    try await custody.destroyKey(keyId)
                } catch let error as PlatformError {
                    guard case .secureEnclaveUnavailable = error else {
                        Issue.record("expected secureEnclaveUnavailable, got \(error)")
                        continue
                    }
                }
            }
            for keyType in [CustodyKeyType.p256, .hpkeP256] {
                #expect(await P256Fixture.cryptoCode {
                    _ = try await provider.generateKeypair(keyType: keyType, role: .operational)
                } == "SCP-CRYPTO-4060")
            }
            #expect(P256Fixture.p256ItemCount() == before, "a failed generation must leave no item in either class")
        }

        /// ADR-025 criterion 7's round trip on a host that has an enclave and
        /// the entitlement: generate, sign, read the public key, verify,
        /// destroy, and confirm the re-fetch fails. No CI lane has such a
        /// host yet; it runs on a signed device build.
        @Test(
            "a Secure Enclave P-256 key round-trips sign, verify and destroy",
            .enabled(if: secureEnclaveAvailable)
        )
        func secureEnclaveRoundTrip() async throws {
            let custody = AppleKeyCustody()
            let keyId = try await custody.generateKeypair(keyType: "p256")
            let digest = P256Fixture.randomDigest()
            let signature = try await custody.sign(keyId, data: digest)
            let publicKey = try await custody.publicKey(keyId)
            #expect(signature.count == 64)
            #expect(P256Fixture.isLowS(signature))
            #expect(try testingP256VerifyStrict(publicKey: publicKey, digest: digest, signature: signature))
            #expect(custody.custodyType(keyId) == "hardware")
            let attestation = try await custody.destroyKey(keyId)
            #expect(attestation.confirmed)
            do {
                _ = try await custody.publicKey(keyId)
                Issue.record("a destroyed enclave key still answered")
            } catch let error as PlatformError {
                expectKeyNotFoundError(error)
            }
        }

        private func expectKeyNotFoundError(_ error: PlatformError) {
            guard case .keyNotFound = error else {
                Issue.record("expected keyNotFound, got \(error)")
                return
            }
        }
    }

#endif // os(iOS) || os(macOS)
