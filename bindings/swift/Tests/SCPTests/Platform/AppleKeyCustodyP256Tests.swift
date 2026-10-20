// P-256 and HPKE P-256 custody tests for `AppleKeyCustody` (ADR-025
// criteria 1, 2, 7, 8 and 9; spec 09 §9.5; spec 03 §3.7.2).
//
// The adapter tests run over `SoftwareP256KeyStore`, the test-only store,
// because an unsigned `swift test` binary can reach neither the Secure
// Enclave nor the data-protection keychain the production store uses. Each
// result is checked against a Rust oracle the `testing` build exports
// (`testingP256VerifyStrict`, `testingP256Ecdh`) or through the bridge's own
// custody object (`TestingCallbackCustody`), never against CryptoKit run on
// the same key. The production store's attribute, query and access-control
// dictionaries are asserted directly, without a keychain.
//
// Every adapter draws its ids from the suite's `KeyIdRecorder`, so a test
// asserts absence for exactly the ids it drew, and `deinit` removes whatever
// those ids left in the Keychain on every exit path.

#if os(iOS) || os(macOS)

    import CryptoKit
    import Foundation
    @testable import SCP
    import Security
    import Testing

    /// Whether this process can mint a Secure Enclave key. The probe builds
    /// its attributes and query with the production store's own static
    /// functions and calls the Security framework directly, never a
    /// `P256KeyStore`, so no store under test can change its answer. An
    /// unsigned `swift test` binary gets `errSecMissingEntitlement` even on a
    /// Mac with an enclave, so `SecureEnclave.isAvailable` is not the
    /// predicate.
    let secureEnclaveAvailable: Bool = {
        let tag = Data("scp.key.enclave-probe-\(UInt64.random(in: .min ... .max))".utf8)
        guard let access = try? KeychainP256KeyStore.accessControl(backing: .secureEnclave, policy: .none) else {
            return false
        }
        let attributes = KeychainP256KeyStore.createAttributes(
            tag: tag, backing: .secureEnclave, accessGroup: nil, accessControl: access
        )
        guard SecKeyCreateRandomKey(attributes as CFDictionary, nil) != nil else { return false }
        SecItemDelete(KeychainP256KeyStore.keyQuery(tag: tag, backing: .secureEnclave, accessGroup: nil) as CFDictionary)
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
    }

    /// The production store's attribute, query and access-control
    /// dictionaries, asserted without a keychain (ADR-025 criteria 2 and 8).
    struct KeychainP256KeyStoreAttributeTests {
        /// On macOS every key query and creation attribute set selects the
        /// data-protection keychain, where an enclave key lives; a query
        /// without the flag searches the file keychain and would report a
        /// live key as gone.
        @Test("the production store selects the data-protection keychain on macOS for both backings", arguments: P256Backing.allCases)
        func productionQueriesUseDataProtection(backing: P256Backing) throws {
            let tag = Data("scp.key.1".utf8)
            let query = KeychainP256KeyStore.keyQuery(tag: tag, backing: backing, accessGroup: "team.dev.limn.scp")
            let attributes = try KeychainP256KeyStore.createAttributes(
                tag: tag,
                backing: backing,
                accessGroup: "team.dev.limn.scp",
                accessControl: KeychainP256KeyStore.accessControl(backing: backing, policy: .none)
            )
            #if os(macOS)
                #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
                #expect(attributes[kSecUseDataProtectionKeychain as String] as? Bool == true)
            #endif
            #expect(query[kSecAttrApplicationTag as String] as? Data == tag)
            #expect(query[kSecAttrAccessGroup as String] as? String == "team.dev.limn.scp")
            #expect(attributes[kSecAttrAccessGroup as String] as? String == "team.dev.limn.scp")
            let privateAttributes = try #require(attributes[kSecPrivateKeyAttrs as String] as? [String: Any])
            #expect(privateAttributes[kSecAttrIsPermanent as String] as? Bool == true)
            #expect(privateAttributes[kSecAttrApplicationTag as String] as? Data == tag)
            #expect(privateAttributes[kSecAttrAccessControl as String] != nil)
            #expect(privateAttributes[kSecAttrAccessGroup as String] as? String == "team.dev.limn.scp")
        }

        @Test("only the enclave backing names the Secure Enclave token", arguments: P256Backing.allCases)
        func tokenIdOnlyForTheEnclave(backing: P256Backing) throws {
            let tag = Data("scp.key.1".utf8)
            let query = KeychainP256KeyStore.keyQuery(tag: tag, backing: backing, accessGroup: nil)
            let attributes = try KeychainP256KeyStore.createAttributes(
                tag: tag,
                backing: backing,
                accessGroup: nil,
                accessControl: KeychainP256KeyStore.accessControl(backing: backing, policy: .none)
            )
            let token = backing == .secureEnclave ? kSecAttrTokenIDSecureEnclave as String : nil
            #expect(query[kSecAttrTokenID as String] as? String == token)
            #expect(attributes[kSecAttrTokenID as String] as? String == token)
            #expect(query[kSecAttrAccessGroup as String] == nil)
        }

        @Test("access control: privateKeyUsage only for the enclave; biometry and WhenUnlocked only under required")
        func accessControlPerBackingAndPolicy() {
            typealias Store = KeychainP256KeyStore
            let afterFirstUnlock = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let whenUnlocked = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            #expect(Store.accessControlSpec(backing: .secureEnclave, policy: .none)
                == .init(protection: afterFirstUnlock, flags: [.privateKeyUsage]))
            #expect(Store.accessControlSpec(backing: .secureEnclave, policy: .required)
                == .init(protection: whenUnlocked, flags: [.privateKeyUsage, .biometryCurrentSet]))
            #expect(Store.accessControlSpec(backing: .software, policy: .none)
                == .init(protection: afterFirstUnlock, flags: []))
            #expect(Store.accessControlSpec(backing: .software, policy: .required)
                == .init(protection: whenUnlocked, flags: [.biometryCurrentSet]))
        }
    }

    extension KeyIdRecorder {
        /// An adapter whose probe reports `enclaveAvailable`, whose mint
        /// backing's store is `store` and whose other backing's store is
        /// `other`, so a key operation routed to the wrong backing finds no
        /// key.
        func p256Adapter(
            _ store: SoftwareP256KeyStore,
            policy: BiometricPolicy = .none,
            enclaveAvailable: Bool = true,
            other: SoftwareP256KeyStore = SoftwareP256KeyStore()
        ) -> AppleKeyCustody {
            let mint: P256Backing = enclaveAvailable ? .secureEnclave : .software
            return custody(policy: policy, enclaveAvailable: enclaveAvailable) { backing in
                backing == mint ? store : other
            }
        }
    }

    /// Signing, agreement, type separation and the custody recorded at mint.
    final class AppleKeyCustodyP256Tests: Sendable {
        private let keyIds = KeyIdRecorder()

        deinit {
            keyIds.purge()
        }

        // MARK: - Signing

        /// The bridge's custody object signs a 32-byte digest with the
        /// adapter's P-256 key. The adapter returns the store's DER; the
        /// bridge converts it to the raw 64-byte `r || s` with a low `s` and
        /// verifies it. Half of all ECDSA signatures have a high `s`, so 32
        /// low ones are chance with probability 2^-32 unless the bridge
        /// normalizes, and the strict verifier accepts each one under the
        /// 33-byte public key, so the digest was signed as given.
        @Test("a P-256 key signs through the bridge into a 64-byte low-s signature the strict verifier accepts")
        func p256SignThroughTheBridgeIsRawLowS() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store)
            let bridge = TestingCallbackCustody(provider: custody)
            let keyId = try await bridge.generateKeypair(keyType: .p256)
            let publicKey = try await bridge.publicKey(keyId: keyId)
            #expect(publicKey.count == 33)
            for _ in 0 ..< 32 {
                let digest = P256Fixture.randomDigest()
                let signature = try await bridge.sign(keyId: keyId, data: digest)
                #expect(signature.count == 64)
                #expect(P256Fixture.isLowS(signature), "s must be in the low half of the group order")
                #expect(try testingP256VerifyStrict(publicKey: publicKey, digest: digest, signature: signature))
            }
            try await bridge.destroyKey(keyId: keyId)
        }

        /// The host returns the platform signer's DER unchanged; conversion
        /// belongs to the bridge alone.
        @Test("AppleKeyCustody.sign returns the store's DER signature")
        func hostSignReturnsDer() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store)
            let keyId = try await custody.generateKeypair(keyType: "p256")
            let signature = try await custody.sign(keyId, data: P256Fixture.randomDigest())
            #expect(signature.first == 0x30, "a DER ECDSA-Sig-Value starts with a SEQUENCE tag")
            #expect(signature.count != 64)
            try await custody.destroyKey(keyId)
        }

        // MARK: - Agreement

        /// The bridge's `dhAgree` over the adapter's HPKE key equals the Rust
        /// ECDH oracle run from the peer's side.
        @Test("an HPKE P-256 key agrees through the bridge to the Rust ECDH oracle's secret")
        func hpkeAgreementMatchesTheOracle() async throws {
            let store = SoftwareP256KeyStore()
            let bridge = TestingCallbackCustody(provider: keyIds.p256Adapter(store))
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
            let custody = keyIds.p256Adapter(store)
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
            let provider: any KeyCustodyProvider = keyIds.p256Adapter(store)
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
            let provider: any KeyCustodyProvider = keyIds.p256Adapter(store)
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

        // MARK: - Custody recorded at mint

        /// A key minted on an enclave host is recorded as hardware custody,
        /// and the bridge's own mapping reads it as hardware, not the
        /// in-memory custody an unrecognised string gets.
        @Test("the bridge reads an enclave-backed record as hardware custody")
        func bridgeSeesEnclaveRecordAsHardware() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store, enclaveAvailable: true)
            let bridge = TestingCallbackCustody(provider: custody)
            for keyType in [CustodyKeyType.p256, .hpkeP256] {
                let keyId = try await bridge.generateKeypair(keyType: keyType)
                #expect(custody.custodyType(keyId: keyId) == "hardware")
                #expect(try bridge.custodyType(keyId: keyId) == "hardware")
                try await bridge.destroyKey(keyId: keyId)
            }
        }

        /// A key minted on a host without an enclave is recorded as software
        /// custody, whatever its type, and the bridge reads it as software.
        @Test("the bridge reads a software-backed record as software custody")
        func bridgeSeesSoftwareRecordAsSoftware() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store, enclaveAvailable: false)
            let bridge = TestingCallbackCustody(provider: custody)
            for keyType in [CustodyKeyType.p256, .hpkeP256] {
                let keyId = try await bridge.generateKeypair(keyType: keyType)
                #expect(custody.custodyType(keyId: keyId) == "software")
                #expect(try bridge.custodyType(keyId: keyId) == "software")
                try await bridge.destroyKey(keyId: keyId)
            }
        }

        /// An identity under `.required` applies the policy to every key it
        /// creates, the HPKE wrapping key included.
        @Test("the biometric policy reaches the store for both P-256 key types")
        func biometricPolicyReachesTheStore() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store, policy: .required)
            let signing = try await custody.generateKeypair(keyType: "p256")
            let wrapping = try await custody.generateKeypair(keyType: "hpke-p256")
            #expect(await store.policies == [.required, .required])
            try await custody.destroyKey(signing)
            try await custody.destroyKey(wrapping)
        }
    }

    /// Backing selection: hosts without an enclave, enclave failures and the production store.
    final class AppleKeyCustodyP256BackingTests: Sendable {
        private let keyIds = KeyIdRecorder()

        deinit {
            keyIds.purge()
        }

        // MARK: - Hosts without a Secure Enclave

        /// Operations dispatch on the backing recorded at mint, not on the
        /// adapter's current probe: a key minted where the enclave was
        /// available keeps using the enclave store after an adapter whose
        /// probe reports no enclave reopens it.
        @Test("a key minted in the enclave stays enclave-backed when a probe without an enclave reopens it")
        func reopenedEnclaveKeyKeepsItsBacking() async throws {
            let enclaveStore = SoftwareP256KeyStore()
            let softwareStore = SoftwareP256KeyStore()
            let minting = keyIds.p256Adapter(enclaveStore, enclaveAvailable: true, other: softwareStore)
            let signing = try await minting.generateKeypair(keyType: "p256")
            let wrapping = try await minting.generateKeypair(keyType: "hpke-p256")

            let reopened = keyIds.p256Adapter(softwareStore, enclaveAvailable: false, other: enclaveStore)
            #expect(reopened.mintBacking == .software)
            let bridge = TestingCallbackCustody(provider: reopened)
            let signingPublic = try await bridge.publicKey(keyId: signing)
            let digest = P256Fixture.randomDigest()
            let signature = try await bridge.sign(keyId: signing, data: digest)
            #expect(try testingP256VerifyStrict(publicKey: signingPublic, digest: digest, signature: signature))
            let peer = P256.KeyAgreement.PrivateKey()
            _ = try await bridge.dhAgree(keyId: wrapping, peerPublic: peer.publicKey.x963Representation)
            #expect(await enclaveStore.signCalls == 1)
            #expect(await enclaveStore.agreeCalls == 1)
            #expect(await softwareStore.signCalls == 0)
            #expect(await softwareStore.agreeCalls == 0)
            for keyId in [signing, wrapping] {
                #expect(reopened.custodyType(keyId: keyId) == "hardware")
                #expect(try bridge.custodyType(keyId: keyId) == "hardware")
                try await bridge.destroyKey(keyId: keyId)
                #expect(await !enclaveStore.contains(tag: reopened.applicationTag(for: keyId)))
            }
        }

        /// Spec 09 §9.5's platform signer: with no enclave, both key types
        /// mint in the software backing, sign and agree correctly, and report
        /// `"software"`, or `"software_biometric"` under `.required`.
        @Test(
            "without an enclave both P-256 types mint as software keys that sign, agree and report software custody",
            arguments: [BiometricPolicy.none, .required]
        )
        func noEnclaveMintsSoftwareKeys(policy: BiometricPolicy) async throws {
            let store = SoftwareP256KeyStore()
            let enclaveStore = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store, policy: policy, enclaveAvailable: false, other: enclaveStore)
            #expect(custody.mintBacking == .software)
            let bridge = TestingCallbackCustody(provider: custody)
            let expected = policy == .none ? "software" : "software_biometric"

            let signing = try await bridge.generateKeypair(keyType: .p256)
            let signingPublic = try await bridge.publicKey(keyId: signing)
            let digest = P256Fixture.randomDigest()
            let signature = try await bridge.sign(keyId: signing, data: digest)
            #expect(try testingP256VerifyStrict(publicKey: signingPublic, digest: digest, signature: signature))

            let wrapping = try await bridge.generateKeypair(keyType: .hpkeP256)
            let wrappingPublic = try await bridge.publicKey(keyId: wrapping)
            let peer = P256.KeyAgreement.PrivateKey()
            let shared = try await bridge.dhAgree(keyId: wrapping, peerPublic: peer.publicKey.x963Representation)
            #expect(try shared == testingP256Ecdh(peerScalar: peer.rawRepresentation, hostPublic: wrappingPublic))

            for keyId in [signing, wrapping] {
                #expect(custody.custodyType(keyId: keyId) == expected)
                #expect(try bridge.custodyType(keyId: keyId) == "software")
            }
            #expect(await enclaveStore.createCalls == 0, "no key may reach the enclave backing")
            try await bridge.destroyKey(keyId: signing)
            try await bridge.destroyKey(keyId: wrapping)
        }

        /// ADR-025 criterion 8: on a host whose probe reports an enclave, an
        /// enclave creation failure is its own typed error, the software
        /// backing is never tried, and the drawn id leaves no item in either
        /// class.
        @Test("an enclave creation failure is a typed error that never selects software and leaves no item")
        func enclaveCreateFailureNeverSelectsSoftware() async throws {
            let enclaveStore = SoftwareP256KeyStore()
            let softwareStore = SoftwareP256KeyStore()
            await enclaveStore.failCreate(with: .secureEnclaveKeyCreationFailed(errSecMissingEntitlement))
            let custody = keyIds.p256Adapter(enclaveStore, enclaveAvailable: true, other: softwareStore)
            let provider: any KeyCustodyProvider = custody
            for keyType in ["p256", "hpke-p256"] {
                do {
                    let keyId = try await custody.generateKeypair(keyType: keyType)
                    Issue.record("generateKeypair(\(keyType)) returned \(keyId) after the enclave failed")
                } catch let error as PlatformError {
                    guard case .secureEnclaveKeyCreationFailed(errSecMissingEntitlement) = error else {
                        Issue.record("expected secureEnclaveKeyCreationFailed, got \(error)")
                        continue
                    }
                }
            }
            #expect(await P256Fixture.cryptoCode {
                _ = try await provider.generateKeypair(keyType: .hpkeP256, role: .operational)
            } == "SCP-CRYPTO-4060")
            #expect(await softwareStore.createCalls == 0, "the software backing must never be tried")
            #expect(keyIds.drawn.count == 3)
            for keyId in keyIds.drawn {
                #expect(!KeyIdRecorder.companionExists(keyId), "no companion may remain for \(keyId)")
                #expect(await !enclaveStore.contains(tag: custody.applicationTag(for: keyId)))
                #expect(await !softwareStore.contains(tag: custody.applicationTag(for: keyId)))
            }
        }

        /// The SDK's public initializer fixes the mint backing from
        /// CryptoKit's enclave probe.
        @Test("the public initializer chooses the backing from the enclave probe")
        func publicInitializerUsesTheProbe() {
            let expected: P256Backing = SecureEnclave.isAvailable ? .secureEnclave : .software
            #expect(AppleKeyCustody().mintBacking == expected)
            #expect(AppleKeyCustody(biometricPolicy: .required).mintBacking == expected)
        }

        // MARK: - Production store

        /// ADR-025 criterion 8 through the production store: with the probe
        /// reporting an enclave the process cannot use (an unsigned test
        /// binary), both P-256 types throw the typed enclave error, the
        /// bridge sees `SCP-CRYPTO-4060`, and no drawn id leaves an item of
        /// either class, so nothing fell back to a software key.
        @Test(
            "an enclave host whose enclave cannot create a key fails closed and leaves no item",
            .enabled(if: !secureEnclaveAvailable)
        )
        func productionEnclaveFailureFailsClosed() async throws {
            let custody = keyIds.custody(enclaveAvailable: true) { backing in
                KeychainP256KeyStore(backing: backing, accessGroup: nil)
            }
            let provider: any KeyCustodyProvider = custody
            for keyType in ["p256", "hpke-p256"] {
                do {
                    let keyId = try await custody.generateKeypair(keyType: keyType)
                    Issue.record("generateKeypair(\(keyType)) returned \(keyId) without a usable enclave")
                } catch let error as PlatformError {
                    guard case .secureEnclaveKeyCreationFailed = error else {
                        Issue.record("expected secureEnclaveKeyCreationFailed, got \(error)")
                        continue
                    }
                }
            }
            for keyType in [CustodyKeyType.p256, .hpkeP256] {
                #expect(await P256Fixture.cryptoCode {
                    _ = try await provider.generateKeypair(keyType: keyType, role: .operational)
                } == "SCP-CRYPTO-4060")
            }
            #expect(keyIds.drawn.count == 4)
            for keyId in keyIds.drawn {
                #expect(!KeyIdRecorder.companionExists(keyId), "no companion may remain for \(keyId)")
                #expect(!KeyIdRecorder.keyItemExists(keyId), "no key item may remain for \(keyId)")
            }
        }

        /// ADR-025 criterion 7's round trip on a host that has an enclave and
        /// the entitlement, under each biometric policy: generate, read the
        /// public key, check custody, destroy, and confirm the re-fetch
        /// fails. Under `.none` the key also signs through the bridge into a
        /// signature the strict verifier accepts; under `.required` a
        /// signature needs a biometric prompt, so that leg stops before
        /// signing. No CI lane has such a host yet; it runs on a signed
        /// device build.
        @Test(
            "a Secure Enclave P-256 key round-trips under each biometric policy",
            .enabled(if: secureEnclaveAvailable),
            arguments: [BiometricPolicy.none, .required]
        )
        func secureEnclaveRoundTrip(policy: BiometricPolicy) async throws {
            let custody = keyIds.custody(policy: policy, enclaveAvailable: true) { backing in
                KeychainP256KeyStore(backing: backing, accessGroup: nil)
            }
            let keyId = try await custody.generateKeypair(keyType: "p256")
            let publicKey = try await custody.publicKey(keyId)
            #expect(publicKey.count == 33)
            #expect(custody.custodyType(keyId) == "hardware")
            if policy == .none {
                let bridge = TestingCallbackCustody(provider: custody)
                let digest = P256Fixture.randomDigest()
                let signature = try await bridge.sign(keyId: keyId, data: digest)
                #expect(signature.count == 64)
                #expect(P256Fixture.isLowS(signature))
                #expect(try testingP256VerifyStrict(publicKey: publicKey, digest: digest, signature: signature))
            }
            let attestation = try await custody.destroyKey(keyId)
            #expect(attestation.confirmed)
            #expect(!KeyIdRecorder.keyItemExists(keyId))
            do {
                _ = try await custody.publicKey(keyId)
                Issue.record("a destroyed enclave key still answered")
            } catch let error as PlatformError {
                guard case .keyNotFound = error else {
                    Issue.record("expected keyNotFound, got \(error)")
                    return
                }
            }
        }
    }

    /// Destruction, failed-mint rollback, persistence and the end-to-end join.
    final class AppleKeyCustodyP256LifecycleTests: Sendable {
        private let keyIds = KeyIdRecorder()

        deinit {
            keyIds.purge()
        }

        // MARK: - Destruction and persistence

        /// Destruction is confirmed by re-fetching the key, not by the
        /// store's own report: a delete that reports success but leaves the
        /// key is `destructionFailed`, and the record of the key survives.
        @Test("destroyKey re-fetches the key and refuses to confirm one that survived deletion")
        func destroyConfirmsByRefetch() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store)
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
            #expect(await store.contains(tag: custody.applicationTag(for: keyId)))
            #expect(custody.custodyType(keyId) == "hardware", "the record of a surviving key must remain")
            await store.keepKeysOnDelete(false)
            try await custody.destroyKey(keyId)
        }

        @Test("a destroyed P-256 key is gone from the store and reports SCP-CRYPTO-4006")
        func destroyedKeyIsGone() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store)
            let provider: any KeyCustodyProvider = custody
            for keyType in [CustodyKeyType.p256, .hpkeP256] {
                let keyId = try await provider.generateKeypair(keyType: keyType, role: .operational)
                let tag = custody.applicationTag(for: keyId)
                #expect(await store.contains(tag: tag))
                let attestation = try await custody.destroyKey(keyId)
                #expect(attestation.confirmed)
                #expect(attestation.method == .softwareOnly)
                #expect(await !store.contains(tag: tag))
                #expect(!KeyIdRecorder.companionExists(keyId))
                #expect(await P256Fixture.cryptoCode { _ = try await provider.getPublicKey(keyId: keyId) } == "SCP-CRYPTO-4006")
                #expect(await P256Fixture.cryptoCode { try await provider.destroyKey(keyId: keyId) } == "SCP-CRYPTO-4006")
                #expect(provider.custodyType(keyId: keyId) == "in_memory")
            }
        }

        /// A mint that fails after creating its key, with a store whose
        /// delete then fails, keeps the companion: it is the only record
        /// naming the key and its backing. The error names the key id, so the
        /// caller can destroy it; `destroyKey` of that id removes both. Through
        /// the bridge the same failure is `SCP-CRYPTO-4060` naming the id.
        @Test("a failed mint whose rollback delete fails names the key id, and destroyKey of it removes both")
        func failedRollbackKeepsTheRecordForDestroy() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store)
            await store.returnInvalidPoint(true)
            await store.failNextDeletes(1)
            var named: String?
            do {
                let keyId = try await custody.generateKeypair(keyType: "p256")
                Issue.record("generateKeypair returned \(keyId) for an off-curve public key")
            } catch let PlatformError.mintRollbackIncomplete(keyId, _) {
                named = keyId
            }
            let keyId = try #require(named, "the error must name the key the rollback left")
            let tag = custody.applicationTag(for: keyId)
            #expect(await store.contains(tag: tag), "the store's delete failed, so the key remains")
            #expect(KeyIdRecorder.companionExists(keyId), "the companion must outlive a key the store still holds")

            let attestation = try await custody.destroyKey(keyId)
            #expect(attestation.confirmed)
            #expect(await !store.contains(tag: tag))
            #expect(!KeyIdRecorder.companionExists(keyId))

            await store.failNextDeletes(1)
            let provider: any KeyCustodyProvider = custody
            do {
                let handle = try await provider.generateKeypair(keyType: .p256, role: .operational)
                Issue.record("the bridge minted \(handle) for an off-curve public key")
            } catch let ScpError.Crypto(msg, code) {
                #expect(code == "SCP-CRYPTO-4060")
                let bridged = try #require(keyIds.drawn.last)
                #expect(msg.contains("'\(bridged)'"), "the bridge error must name the key id: \(msg)")
                _ = try await custody.destroyKey(bridged)
            }
        }

        /// A failed mint whose store deletes cleanly leaves nothing.
        @Test("a failed mint whose rollback succeeds leaves no item for the drawn id")
        func failedMintRollsBackCompletely() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store)
            await store.returnInvalidPoint(true)
            await #expect(throws: PlatformError.self) {
                _ = try await custody.generateKeypair(keyType: "p256")
            }
            let keyId = try #require(keyIds.drawn.last)
            #expect(await !store.contains(tag: custody.applicationTag(for: keyId)))
            #expect(!KeyIdRecorder.companionExists(keyId))
        }

        /// A key whose companion is gone, as an interrupted cleanup leaves
        /// it, is still found through the store and deleted.
        @Test("destroyKey deletes an orphaned key whose companion is missing")
        func destroyDeletesAnOrphanWithoutACompanion() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store)
            let keyId = keyIds.next()
            let tag = custody.applicationTag(for: keyId)
            try await store.plant(tag: tag)

            let attestation = try await custody.destroyKey(keyId)
            #expect(attestation.confirmed)
            #expect(await !store.contains(tag: tag))
        }

        /// A key whose companion no longer decodes is still found through
        /// the store and deleted, and the companion goes with it.
        @Test("destroyKey deletes an orphaned key whose companion does not decode")
        func destroyDeletesAnOrphanWithAnUndecodableCompanion() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store)
            let keyId = keyIds.next()
            let tag = custody.applicationTag(for: keyId)
            try await store.plant(tag: tag)
            let status = SecItemAdd([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "scp.key.\(keyId)",
                kSecAttrLabel as String: "not metadata"
            ] as CFDictionary, nil)
            #expect(status == errSecSuccess)

            let attestation = try await custody.destroyKey(keyId)
            #expect(attestation.confirmed)
            #expect(await !store.contains(tag: tag))
            #expect(!KeyIdRecorder.companionExists(keyId))
        }

        /// A new adapter over the same store (an app restart) finds the key.
        /// This covers only the companion item, which keeps the type, role,
        /// backing and public key across instances: the test store holds its
        /// keys in process, so the private key's persistence is the
        /// production store's and is exercised on a signed device build.
        @Test("an HPKE P-256 key's companion survives a new adapter over the same store")
        func hpkeCompanionSurvivesARestart() async throws {
            let store = SoftwareP256KeyStore()
            let first: any KeyCustodyProvider = keyIds.p256Adapter(store)
            let keyId = try await first.generateKeypair(keyType: .hpkeP256, role: .identity)
            let before = try await first.getPublicKey(keyId: keyId)

            let second: any KeyCustodyProvider = keyIds.p256Adapter(store)
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
        /// adapter's `dhAgree`. Both instances shut down and every key the
        /// adapter minted is destroyed on every exit path.
        @Test("a joiner whose custody is the adapter opens a sealed invitation")
        func joinerOpensASealedInvitation() async throws {
            let store = SoftwareP256KeyStore()
            let custody = keyIds.p256Adapter(store)
            let creatorScp = try SCP(storage: .inMemory)
            let joinerScp = try SCP(storage: .inMemory)

            var failure: (any Error)?
            do {
                try await joinAndOpen(creatorScp: creatorScp, joinerScp: joinerScp, custody: custody, store: store)
            } catch {
                failure = error
            }
            do {
                try await creatorScp.shutdown(timeoutMillis: 1000)
                try await joinerScp.shutdown(timeoutMillis: 1000)
            } catch {
                failure = failure ?? error
            }
            for keyId in keyIds.drawn {
                do {
                    try await custody.destroyKey(keyId)
                } catch PlatformError.keyNotFound {
                    // Consumed by the join, or never created.
                } catch {
                    failure = failure ?? error
                }
                #expect(!KeyIdRecorder.companionExists(keyId))
                #expect(await !store.contains(tag: custody.applicationTag(for: keyId)))
            }
            if let failure {
                throw failure
            }
        }

        private func joinAndOpen(
            creatorScp: SCP,
            joinerScp: SCP,
            custody: AppleKeyCustody,
            store: SoftwareP256KeyStore
        ) async throws {
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
        }
    }

#endif // os(iOS) || os(macOS)
