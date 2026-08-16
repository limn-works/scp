// Fail-closed and rejection tests for adapter `AppleDeviceAttestation`.
//
// These tests pin two properties of `AppleDeviceAttestation`:
//
// 1. When `DCAppAttestService.isSupported` is `false`, `attest` and
//    `assertRequest` throw `AttestationError.unsupported` and return no bytes.
//    §9.3 of SCP's security model spec, "Sybil resistance and identity
//    uniqueness", states that a DID carrying no device attestation loses
//    nothing for that absence, so a typed error is an honest result and a
//    locally minted token would assert a hardware guarantee no hardware
//    produced.
// 2. `verify(token:)` accepts a token satisfying all four clauses of
//    acceptance criterion 3 in ADR-025, and rejects every token that fails a
//    clause. Each case below that expects `false` names which clause it breaks.
// 3. Concurrent first calls to `attest` generate one App Attest key, because
//    `resolveKeyId` reads a stored key ID and publishes its generation task
//    inside one critical section.
//
// Four clauses ADR-025 states, in `.docs/adrs/phase-5.md`:
//
// 1. Token bytes decode as a CBOR map whose key set is exactly `fmt`, `attStmt`,
//    `authData`.
// 2. `fmt` is CBOR text string `apple-appattest`.
// 3. `attStmt` is a CBOR map whose key set is exactly `x5c`, `receipt`, where
//    `x5c` is an array of at least two byte strings that each parse as a DER
//    X.509 certificate, element 0 is a credential certificate and element 1 is
//    an Apple App Attest intermediate certificate, and `receipt` is a byte
//    string. `readCertificateChain` decides two distinct certificates whose
//    element 0 names element 1 by subject name, and leaves which authority
//    element 1 belongs to for an SCP relay; cases below test what that method
//    decides, not what a relay decides.
// 4. `authData` is a byte string of at least 87 bytes: bytes 0 through 31
//    hold a relying-party ID hash and equal SHA-256 of an app's App ID, byte
//    32 holds flags, bytes 33 through 36 hold a sign counter, bytes 37 through
//    52 hold an AAGUID and equal `appattest` or `appattestdevelop` padded to
//    16 bytes with zero bytes, bytes 53 and 54 hold a credential-ID length and
//    equal 0x0020, and bytes 55 through 86 hold a credential ID.
//
// See ADR-025 (Apple Platform Adapter) in `.docs/adrs/phase-5.md` and
// `crates/scp-platform/src/traits.rs` `DeviceAttestation`.

#if os(iOS) || os(macOS)

    import CryptoKit
    import DeviceCheck
    import Foundation
    @testable import SCP
    import Testing

    // MARK: - Test doubles

    /// A `DCAppAttestService` that reports App Attest as unavailable, which is
    /// what a simulator reports, and what every device without a Secure
    /// Enclave App Attest key reports.
    private final class UnsupportedAppAttestService: DCAppAttestService, @unchecked Sendable {
        override var isSupported: Bool {
            false
        }
    }

    /// A `DCAppAttestService` that reports App Attest as available and counts
    /// how many times a caller asked it to generate a key.
    private final class CountingAppAttestService: DCAppAttestService, @unchecked Sendable {
        /// A key ID this double hands back to every caller.
        static let keyId = "counting-service-key-id"

        private let lock = NSLock()
        private var callCount = 0

        /// How many times `generateKey` ran.
        var keyGenerationCount: Int {
            lock.withLock { callCount }
        }

        override var isSupported: Bool {
            true
        }

        override func generateKey(completionHandler: @escaping (String?, Error?) -> Void) {
            lock.withLock { callCount += 1 }
            // Apple's App Attest service answers from Secure Enclave hardware
            // over milliseconds, not instantly. Answering on a later turn holds
            // open a window in which a second caller can observe that no key ID
            // is stored yet.
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.02) {
                completionHandler(Self.keyId, nil)
            }
        }

        override func attestKey(
            _: String,
            clientDataHash _: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            completionHandler(Data([0x01, 0x02, 0x03]), nil)
        }
    }

    /// A `DCAppAttestService` that reports App Attest as available and answers
    /// every `attestKey` call with `DCError.invalidKey`, which Apple returns
    /// when a key ID no longer names a usable Secure Enclave key.
    private final class InvalidKeyAppAttestService: DCAppAttestService, @unchecked Sendable {
        override var isSupported: Bool {
            true
        }

        override func generateKey(completionHandler: @escaping (String?, Error?) -> Void) {
            completionHandler("regenerated-key-id", nil)
        }

        override func attestKey(
            _: String,
            clientDataHash _: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            completionHandler(nil, Self.invalidKeyError)
        }

        override func generateAssertion(
            _: String,
            clientDataHash _: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            completionHandler(nil, Self.invalidKeyError)
        }

        /// What Apple returns when a key ID no longer names a usable key.
        static let invalidKeyError = NSError(
            domain: DCErrorDomain,
            code: DCError.invalidKey.rawValue,
            userInfo: nil
        )
    }

    /// A `DCAppAttestService` that answers each call from a script.
    ///
    /// Apple returns one error code, `DCError.invalidKey`, for three different
    /// conditions, and which condition holds depends on call order and on
    /// whether a key was attested. Scripting answers per call lets one test
    /// reproduce one real order — two attestations in a row, or an attestation
    /// that failed followed by an assertion — rather than one canned failure.
    ///
    /// Each script is consumed front to back, and its last entry answers every
    /// call after it.
    private final class ScriptedAppAttestService: DCAppAttestService, @unchecked Sendable {
        /// A key ID `generateKey` hands back.
        static let generatedKeyId = "scripted-generated-key-id"

        /// What Apple returns for each of three `DCError.invalidKey` conditions.
        static let invalidKeyError = NSError(
            domain: DCErrorDomain,
            code: DCError.invalidKey.rawValue,
            userInfo: nil
        )

        /// What Apple returns when it cannot reach its App Attest service.
        static let serverUnavailableError = NSError(
            domain: DCErrorDomain,
            code: DCError.serverUnavailable.rawValue,
            userInfo: nil
        )

        private let lock = NSLock()
        private var attestScript: [Result<Data, Error>]
        private var assertScript: [Result<Data, Error>]
        private var keyGenerationCallCount = 0

        /// How many times `generateKey` ran.
        var keyGenerationCount: Int {
            lock.withLock { keyGenerationCallCount }
        }

        init(
            attestScript: [Result<Data, Error>] = [.failure(ScriptedAppAttestService.invalidKeyError)],
            assertScript: [Result<Data, Error>] = [.failure(ScriptedAppAttestService.invalidKeyError)]
        ) {
            self.attestScript = attestScript
            self.assertScript = assertScript
            super.init()
        }

        override var isSupported: Bool {
            true
        }

        override func generateKey(completionHandler: @escaping (String?, Error?) -> Void) {
            lock.withLock { keyGenerationCallCount += 1 }
            completionHandler(Self.generatedKeyId, nil)
        }

        override func attestKey(
            _: String,
            clientDataHash _: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            answer(from: \.attestScript, to: completionHandler)
        }

        override func generateAssertion(
            _: String,
            clientDataHash _: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            answer(from: \.assertScript, to: completionHandler)
        }

        /// Take a script's next entry, keeping its last entry in place.
        private func answer(
            from script: ReferenceWritableKeyPath<ScriptedAppAttestService, [Result<Data, Error>]>,
            to completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            let next: Result<Data, Error>? = lock.withLock {
                guard let first = self[keyPath: script].first else { return nil }
                if self[keyPath: script].count > 1 {
                    self[keyPath: script].removeFirst()
                }
                return first
            }
            switch next {
            case let .success(data):
                completionHandler(data, nil)
            case let .failure(error):
                completionHandler(nil, error)
            case nil:
                completionHandler(nil, Self.invalidKeyError)
            }
        }
    }

    /// A `UserDefaults` that keeps every value in memory.
    ///
    /// `AppleDeviceAttestation` reads, writes, and removes one string key, so
    /// overriding those three methods covers every call it makes. A real
    /// `UserDefaults(suiteName:)` would leave one
    /// `~/Library/Preferences/<suiteName>.plist` behind per test, because
    /// `removePersistentDomain(forName:)` clears values and leaves that file,
    /// and because `cfprefsd` may write it after a test deleted it. Keeping
    /// values in memory writes nothing to delete.
    private final class InMemoryUserDefaults: UserDefaults, @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [String: String] = [:]

        override func string(forKey defaultName: String) -> String? {
            lock.withLock { storage[defaultName] }
        }

        override func set(_ value: Any?, forKey defaultName: String) {
            lock.withLock { storage[defaultName] = value as? String }
        }

        override func removeObject(forKey defaultName: String) {
            lock.withLock { storage[defaultName] = nil }
        }
    }

    // MARK: - CBOR fixtures

    /// Builds CBOR byte sequences these tests feed to `verify(token:)`.
    ///
    /// This encoder covers only a definite-length subset an App Attest
    /// attestation object uses, which is all these fixtures need.
    private enum CBORFixture {
        /// A `fmt` value Apple writes into a genuine attestation object.
        static let appleFormat = "apple-appattest"

        /// An App ID every adapter under test is initialized with, written as
        /// Apple writes an App ID: `<team ID>.<bundle ID>`.
        static let appId = "A1B2C3D4E5.dev.limn.scp.tests"

        /// A different app's App ID, used to build authenticator data that
        /// clause 4 rejects.
        static let foreignAppId = "Z9Y8X7W6V5.example.other.app"

        /// An AAGUID a production App Attest key carries.
        static let productionAaguid = [UInt8]("appattest".utf8) + [UInt8](repeating: 0, count: 7)

        /// An AAGUID a development App Attest key carries.
        static let developmentAaguid = [UInt8]("appattestdevelop".utf8)

        /// A credential-ID length App Attest writes: 32 as a big-endian
        /// `UInt16`.
        static let credentialIdLength: [UInt8] = [0x00, 0x20]

        /// A 32-byte credential ID. Clause 4 constrains no byte of it.
        static let credentialId = [UInt8](repeating: 0x5C, count: 32)

        /// A P-256 certificate in DER form, standing in for an App Attest
        /// credential certificate. `intermediateCertificate` issued it, so its
        /// issuer name equals that certificate's subject name, which is what
        /// clause 3 requires of element 0 of `x5c`.
        ///
        /// Which certification authority element 1 belongs to stays outside
        /// `verify(token:)`. An SCP relay decides whether a chain reaches
        /// Apple's App Attest root.
        static let credentialCertificate = der(
            """
            MIIBmDCCAT6gAwIBAgIUaqvd+exYmYSALlFVQ/W0O2uFQAEwCgYIKoZIzj0EAwIwKjEoMCYGA1UE
            AwwfU0NQIEFwcEF0dGVzdCBUZXN0IEludGVybWVkaWF0ZTAgFw0yNjA4MTYxNjAwMjJaGA8yMTI2
            MDcyMzE2MDAyMlowKDEmMCQGA1UEAwwdU0NQIEFwcEF0dGVzdCBUZXN0IENyZWRlbnRpYWwwWTAT
            BgcqhkjOPQIBBggqhkjOPQMBBwNCAAQOQ8ei3oFlCZE+Lp6aQV+67h6D8A1UHWenpFK6oM+kMsOf
            w1kuvOnVCX6dPdVa8MH+zbPBntYm3btEN5gAZYjzo0IwQDAdBgNVHQ4EFgQUnVR1Sv2Fh0JTW/1r
            riMF1nn/WIEwHwYDVR0jBBgwFoAUhc+NPUBeXkD6U7Roxriq9NNpi+AwCgYIKoZIzj0EAwIDSAAw
            RQIhANy3qzCL6l/7kTxQytH6MivRZVjwuj5K1257x0whAu0EAiARri/mndaidpfhN1szKhbF8FYn
            SXA7MCtxCCiCmPGWGQ==
            """
        )

        /// A self-signed P-256 CA certificate in DER form, standing in for an
        /// Apple App Attest intermediate certificate. It issued
        /// `credentialCertificate`.
        static let intermediateCertificate = der(
            """
            MIIBqzCCAVGgAwIBAgIUBoSfz3ohRs4uQwLxpOgtSK5iKoswCgYIKoZIzj0EAwIwKjEoMCYGA1UE
            AwwfU0NQIEFwcEF0dGVzdCBUZXN0IEludGVybWVkaWF0ZTAgFw0yNjA4MTYxNjAwMjJaGA8yMTI2
            MDcyMzE2MDAyMlowKjEoMCYGA1UEAwwfU0NQIEFwcEF0dGVzdCBUZXN0IEludGVybWVkaWF0ZTBZ
            MBMGByqGSM49AgEGCCqGSM49AwEHA0IABLCFR8VwPEdorNei7Sy+3XFYqhHOaTLPuoazLFC21QKz
            XuE0zNL3fk+Q7J/ZzkewmKrAriXOZTrmFFRoMJWsVQGjUzBRMB0GA1UdDgQWBBSFz409QF5eQPpT
            tGjGuKr002mL4DAfBgNVHSMEGDAWgBSFz409QF5eQPpTtGjGuKr002mL4DAPBgNVHRMBAf8EBTAD
            AQH/MAoGCCqGSM49BAMCA0gAMEUCIA++aHRExYw6JSqFxZG4dV6CBQqCLYkcGYGr8mcGCFE8AiEA
            9kzA+7bOXbfHds/deoZU063YywGSGsfz7z0vvPAKhrI=
            """
        )

        /// `credentialCertificate` with one byte changed: its issuer name's
        /// first `RelativeDistinguishedName` carries tag `SEQUENCE` where X.501
        /// requires `SET`. Every enclosing length stays valid, so
        /// `SecCertificateCreateWithData` still parses it, while
        /// `SecCertificateCopyNormalizedIssuerSequence` returns nil for it —
        /// which is a branch `readCertificateChain` fails closed on.
        static let retaggedIssuerCertificate = der(
            """
            MIIBmDCCAT6gAwIBAgIUaqvd+exYmYSALlFVQ/W0O2uFQAEwCgYIKoZIzj0EAwIwKjAoMCYGA1UE
            AwwfU0NQIEFwcEF0dGVzdCBUZXN0IEludGVybWVkaWF0ZTAgFw0yNjA4MTYxNjAwMjJaGA8yMTI2
            MDcyMzE2MDAyMlowKDEmMCQGA1UEAwwdU0NQIEFwcEF0dGVzdCBUZXN0IENyZWRlbnRpYWwwWTAT
            BgcqhkjOPQIBBggqhkjOPQMBBwNCAAQOQ8ei3oFlCZE+Lp6aQV+67h6D8A1UHWenpFK6oM+kMsOf
            w1kuvOnVCX6dPdVa8MH+zbPBntYm3btEN5gAZYjzo0IwQDAdBgNVHQ4EFgQUnVR1Sv2Fh0JTW/1r
            riMF1nn/WIEwHwYDVR0jBBgwFoAUhc+NPUBeXkD6U7Roxriq9NNpi+AwCgYIKoZIzj0EAwIDSAAw
            RQIhANy3qzCL6l/7kTxQytH6MivRZVjwuj5K1257x0whAu0EAiARri/mndaidpfhN1szKhbF8FYn
            SXA7MCtxCCiCmPGWGQ==
            """
        )

        /// A self-signed P-256 certificate in DER form that issued nothing and
        /// that `intermediateCertificate` did not issue. Clause 3 rejects it in
        /// either position of a two-element `x5c`.
        static let unrelatedCertificate = der(
            """
            MIIBpDCCAUugAwIBAgIUXUwOxX/jZnCGvEIsev4suB/T1+AwCgYIKoZIzj0EAwIwJzElMCMGA1UE
            AwwcU0NQIEFwcEF0dGVzdCBUZXN0IFVucmVsYXRlZDAgFw0yNjA4MTYxNjAwMjJaGA8yMTI2MDcy
            MzE2MDAyMlowJzElMCMGA1UEAwwcU0NQIEFwcEF0dGVzdCBUZXN0IFVucmVsYXRlZDBZMBMGByqG
            SM49AgEGCCqGSM49AwEHA0IABBgdZ2UJilP8TlRzMkS8rSdP+LfA6s48yIT/7ibqCOReWQ3HfdYU
            3y9Zl/timyOCuyMxwiP2I6LwCpWD89Nfog+jUzBRMB0GA1UdDgQWBBQOSVOdgm1GyX08bBRipu/R
            vDykKjAfBgNVHSMEGDAWgBQOSVOdgm1GyX08bBRipu/RvDykKjAPBgNVHRMBAf8EBTADAQH/MAoG
            CCqGSM49BAMCA0cAMEQCIHsAmmvJ63Y9coR1rm7koMDTIlm6CKfWqnnWsKn2vB5VAiB/Ih+wj+Ob
            E9uIhsiI38DjpMDeyQ6tSz/nftMmVyfcAg==
            """
        )

        /// Decode a base64 certificate literal, ignoring line breaks that
        /// literal carries for readability.
        static func der(_ base64: String) -> [UInt8] {
            guard let data = Data(base64Encoded: base64, options: .ignoreUnknownCharacters) else {
                return []
            }
            return [UInt8](data)
        }

        /// SHA-256 of an App ID, which clause 4 requires bytes 0 through 31 of
        /// authenticator data to equal.
        static func relyingPartyIdHash(of appId: String) -> [UInt8] {
            Array(SHA256.hash(data: Data(appId.utf8)))
        }

        /// Encode one CBOR item head for `major` carrying `argument`.
        static func head(major: UInt8, argument: Int) -> [UInt8] {
            let prefix = major << 5
            if argument <= 23 {
                return [prefix | UInt8(argument)]
            }
            if argument <= 0xFF {
                return [prefix | 24, UInt8(argument)]
            }
            return [prefix | 25, UInt8((argument >> 8) & 0xFF), UInt8(argument & 0xFF)]
        }

        static func text(_ value: String) -> [UInt8] {
            let utf8 = [UInt8](value.utf8)
            return head(major: 3, argument: utf8.count) + utf8
        }

        static func byteString(_ value: [UInt8]) -> [UInt8] {
            head(major: 2, argument: value.count) + value
        }

        static func mapHeader(_ entryCount: Int) -> [UInt8] {
            head(major: 5, argument: entryCount)
        }

        static func arrayHeader(_ elementCount: Int) -> [UInt8] {
            head(major: 4, argument: elementCount)
        }

        /// Assemble authenticator data, letting a caller vary one field so a
        /// test can name one property it broke.
        static func authenticatorData(
            appId: String = CBORFixture.appId,
            flags: UInt8 = 0x40,
            signCounter: [UInt8] = [0x00, 0x00, 0x00, 0x01],
            aaguid: [UInt8] = CBORFixture.productionAaguid,
            credentialIdLength: [UInt8] = CBORFixture.credentialIdLength,
            credentialId: [UInt8] = CBORFixture.credentialId
        ) -> [UInt8] {
            relyingPartyIdHash(of: appId)
                + [flags]
                + signCounter
                + aaguid
                + credentialIdLength
                + credentialId
        }

        /// Assemble an `attStmt` value Apple returns: a certificate chain plus
        /// a receipt.
        static func attestationStatement(
            certificates: [[UInt8]] = [
                CBORFixture.credentialCertificate,
                CBORFixture.intermediateCertificate
            ],
            receipt: [UInt8] = [UInt8](repeating: 0x0A, count: 6)
        ) -> [UInt8] {
            var out = mapHeader(2)
            out += text("x5c")
            out += arrayHeader(certificates.count)
            for certificate in certificates {
                out += byteString(certificate)
            }
            out += text("receipt")
            out += byteString(receipt)
            return out
        }

        /// Assemble an attestation object, letting a caller replace one encoded
        /// value so a test can name one property it broke.
        ///
        /// Both value parameters take already-encoded CBOR bytes, so a test can
        /// hand `attStmt` or `authData` an item of a wrong major type.
        static func attestationObject(
            format: String = CBORFixture.appleFormat,
            attestationStatementValue: [UInt8] = CBORFixture.attestationStatement(),
            authenticatorDataValue: [UInt8] = CBORFixture.byteString(
                CBORFixture.authenticatorData()
            ),
            extraKey: String? = nil
        ) -> Data {
            let entryCount = extraKey == nil ? 3 : 4
            var out = mapHeader(entryCount)
            out += text("fmt") + text(format)
            out += text("attStmt") + attestationStatementValue
            out += text("authData") + authenticatorDataValue
            if let extraKey {
                out += text(extraKey) + text("value")
            }
            return Data(out)
        }
    }

    // MARK: - Helpers

    /// An adapter under test, together with a defaults store it writes to.
    private struct AttestationHarness {
        let adapter: AppleDeviceAttestation
        let defaults: UserDefaults
    }

    /// Build an adapter whose App Attest service reports itself unavailable.
    private func makeUnsupportedAdapter() -> AttestationHarness {
        let defaults = InMemoryUserDefaults()
        let adapter = AppleDeviceAttestation(
            appId: CBORFixture.appId,
            service: UnsupportedAppAttestService(),
            defaults: defaults
        )
        return AttestationHarness(adapter: adapter, defaults: defaults)
    }

    // MARK: - Fail-closed tests

    struct AppleDeviceAttestationFailClosedTests {
        @Test("attest throws AttestationError.unsupported when App Attest is unavailable")
        func attestThrowsUnsupported() async throws {
            let harness = makeUnsupportedAdapter()
            let adapter = harness.adapter

            do {
                let token = try await adapter.attest(
                    challenge: Data([0x01, 0x02, 0x03]),
                    deviceId: Data([0x04, 0x05, 0x06])
                )
                Issue.record(
                    "attest returned \(token.count) bytes on a device without App Attest instead of throwing"
                )
            } catch let error as AttestationError {
                guard case let .unsupported(reason) = error else {
                    Issue.record("attest threw \(error) instead of AttestationError.unsupported")
                    return
                }
                #expect(reason.contains("isSupported"))
            }
        }

        @Test("assertRequest throws AttestationError.unsupported when App Attest is unavailable")
        func assertRequestThrowsUnsupported() async throws {
            let harness = makeUnsupportedAdapter()
            let adapter = harness.adapter

            do {
                let assertion = try await adapter.assertRequest(
                    requestHash: Data(repeating: 0xAB, count: 32)
                )
                Issue.record(
                    "assertRequest returned \(assertion.count) bytes on a device without App Attest instead of throwing"
                )
            } catch let error as AttestationError {
                guard case let .unsupported(reason) = error else {
                    Issue.record(
                        "assertRequest threw \(error) instead of AttestationError.unsupported"
                    )
                    return
                }
                #expect(reason.contains("isSupported"))
            }
        }

        @Test("a failed attest stores no App Attest key ID")
        func failedAttestStoresNoKeyId() async {
            let harness = makeUnsupportedAdapter()
            let adapter = harness.adapter

            _ = try? await adapter.attest(challenge: Data([0x01]), deviceId: Data([0x02]))

            #expect(harness.defaults.string(forKey: "dev.limn.scp.appAttest.keyId") == nil)
        }

        @Test("isHardwareBacked reports false when App Attest is unavailable")
        func isHardwareBackedReportsFalse() {
            let harness = makeUnsupportedAdapter()
            let adapter = harness.adapter

            #expect(adapter.isHardwareBacked == false)
        }

        @Test("concurrent first attests generate one App Attest key, over 50 rounds")
        func concurrentAttestsGenerateOneKey() async {
            // A caller that reads absence in one critical section and publishes
            // its generation task in another lets a second caller read absence
            // too, and a device ends up holding two Secure Enclave App Attest
            // keys. Eight callers racing on one fresh adapter expose that split
            // whenever it exists; 50 rounds keep a scheduler that happens to
            // serialize one round from hiding it.
            for round in 0 ..< 50 {
                let defaults = InMemoryUserDefaults()
                let service = CountingAppAttestService()
                let adapter = AppleDeviceAttestation(
                    appId: CBORFixture.appId,
                    service: service,
                    defaults: defaults
                )

                await withTaskGroup(of: Void.self) { group in
                    for caller in 0 ..< 8 {
                        group.addTask {
                            _ = try? await adapter.attest(
                                challenge: Data([UInt8(caller)]),
                                deviceId: Data([0x02])
                            )
                        }
                    }
                }

                #expect(
                    service.keyGenerationCount == 1,
                    "round \(round) generated \(service.keyGenerationCount) App Attest keys"
                )
                #expect(
                    defaults.string(forKey: "dev.limn.scp.appAttest.keyId")
                        == CountingAppAttestService.keyId
                )
            }
        }
    }

    // MARK: - App Attest key lifecycle

    /// `DCError.h` lists three conditions behind `DCErrorInvalidKey`: calling
    /// `attestKey:clientDataHash:completionHandler:` for a key already attested,
    /// calling `generateAssertion:clientDataHash:completionHandler:` with an
    /// unattested key, and an App Attest service rejecting a key. Only a third
    /// condition means a key is gone, so only a third condition discards a key
    /// ID. Each case below drives one condition and pins what happens to that
    /// key ID, so collapsing three conditions back into one fails a case.
    struct AppAttestKeyLifecycleTests {
        private static let keyIdStorageKey = "dev.limn.scp.appAttest.keyId"
        private static let attestedKeyIdStorageKey = "dev.limn.scp.appAttest.attestedKeyId"
        private static let storedKeyId = "stored-key-id"

        /// Build an adapter over a scripted service and a defaults store that
        /// already holds `storedKeyId`.
        private func makeAdapter(
            attestScript: [Result<Data, Error>] = [.failure(ScriptedAppAttestService.invalidKeyError)],
            assertScript: [Result<Data, Error>] = [.failure(ScriptedAppAttestService.invalidKeyError)],
            attested: Bool
        ) -> (adapter: AppleDeviceAttestation, defaults: InMemoryUserDefaults) {
            let defaults = InMemoryUserDefaults()
            defaults.set(Self.storedKeyId, forKey: Self.keyIdStorageKey)
            if attested {
                defaults.set(Self.storedKeyId, forKey: Self.attestedKeyIdStorageKey)
            }
            let adapter = AppleDeviceAttestation(
                appId: CBORFixture.appId,
                service: ScriptedAppAttestService(
                    attestScript: attestScript,
                    assertScript: assertScript
                ),
                defaults: defaults
            )
            return (adapter, defaults)
        }

        @Test("attest keeps a key Apple already attested and reports that condition")
        func attestKeepsAlreadyAttestedKey() async {
            let harness = makeAdapter(attested: true)

            await #expect(throws: AttestationError.self) {
                _ = try await harness.adapter.attest(
                    challenge: Data([0x01]),
                    deviceId: Data([0x02])
                )
            }

            // Apple answers `invalidKey` for a second attestation of one key,
            // and that key is alive. Discarding it here strands a live Secure
            // Enclave key and burns one key per two `attest` calls.
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == Self.storedKeyId)
            #expect(
                harness.defaults.string(forKey: Self.attestedKeyIdStorageKey) == Self.storedKeyId
            )
        }

        @Test("attest reports keyAlreadyAttested when Apple attested this key")
        func attestReportsAlreadyAttested() async throws {
            let harness = makeAdapter(attested: true)

            do {
                _ = try await harness.adapter.attest(
                    challenge: Data([0x01]),
                    deviceId: Data([0x02])
                )
                Issue.record("attest returned bytes for a key Apple already attested")
            } catch let error as AttestationError {
                guard case .keyAlreadyAttested = error else {
                    Issue.record("attest threw \(error) instead of AttestationError.keyAlreadyAttested")
                    return
                }
            }
        }

        @Test("assertRequest keeps an unattested key and reports that condition")
        func assertRequestKeepsUnattestedKey() async {
            let harness = makeAdapter(attested: false)

            await #expect(throws: AttestationError.self) {
                _ = try await harness.adapter.assertRequest(
                    requestHash: Data(repeating: 0xAB, count: 32)
                )
            }

            // Apple answers `invalidKey` for an assertion over an unattested
            // key, and that key is alive and awaiting attestation. Discarding it
            // throws away a key Apple's own guidance says to attest later.
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == Self.storedKeyId)
        }

        @Test("assertRequest reports keyNotAttested when Apple attested no key")
        func assertRequestReportsNotAttested() async throws {
            let harness = makeAdapter(attested: false)

            do {
                _ = try await harness.adapter.assertRequest(
                    requestHash: Data(repeating: 0xAB, count: 32)
                )
                Issue.record("assertRequest returned bytes for an unattested key")
            } catch let error as AttestationError {
                guard case .keyNotAttested = error else {
                    Issue.record("assertRequest threw \(error) instead of AttestationError.keyNotAttested")
                    return
                }
            }
        }

        @Test("attest discards an unattested key Apple's service rejected")
        func attestDiscardsRejectedKey() async {
            let harness = makeAdapter(attested: false)

            await #expect(throws: AttestationError.self) {
                _ = try await harness.adapter.attest(
                    challenge: Data([0x01]),
                    deviceId: Data([0x02])
                )
            }

            // No attestation exists for this key, so `invalidKey` from
            // `attestKey` names a rejected key. Keeping it would fail every
            // later `attest` against a dead key.
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == nil)
        }

        @Test("assertRequest discards an attested key Apple's service rejected")
        func assertRequestDiscardsRejectedKey() async {
            let harness = makeAdapter(attested: true)

            await #expect(throws: AttestationError.self) {
                _ = try await harness.adapter.assertRequest(
                    requestHash: Data(repeating: 0xAB, count: 32)
                )
            }

            // An attestation exists for this key, so `invalidKey` from
            // `generateAssertion` names a rejected key — which is how a device
            // restored from a backup recovers.
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == nil)
            #expect(harness.defaults.string(forKey: Self.attestedKeyIdStorageKey) == nil)
        }

        @Test("attest keeps its key when Apple cannot reach its App Attest service")
        func attestKeepsKeyOnServerUnavailable() async {
            let harness = makeAdapter(
                attestScript: [.failure(ScriptedAppAttestService.serverUnavailableError)],
                attested: false
            )

            do {
                _ = try await harness.adapter.attest(
                    challenge: Data([0x01]),
                    deviceId: Data([0x02])
                )
                Issue.record("attest returned bytes while Apple's service was unavailable")
            } catch let error as AttestationError {
                guard case .serverUnavailable = error else {
                    Issue.record("attest threw \(error) instead of AttestationError.serverUnavailable")
                    return
                }
            } catch {
                Issue.record("attest threw \(error) instead of an AttestationError")
            }

            // `DCError.h` says to retry that attestation later using this same
            // key, because retrying with same inputs preserves a device's risk
            // metric.
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == Self.storedKeyId)
        }

        @Test("two attests in a row keep one key, and an assertion still reaches it")
        func repeatedAttestKeepsOneKey() async throws {
            let defaults = InMemoryUserDefaults()
            let assertion = Data([0xAA, 0xBB])
            let service = ScriptedAppAttestService(
                attestScript: [
                    .success(Data([0x01, 0x02, 0x03])),
                    .failure(ScriptedAppAttestService.invalidKeyError)
                ],
                assertScript: [.success(assertion)]
            )
            let adapter = AppleDeviceAttestation(
                appId: CBORFixture.appId,
                service: service,
                defaults: defaults
            )

            // First attestation succeeds and records which key Apple attested.
            _ = try await adapter.attest(challenge: Data([0x01]), deviceId: Data([0x02]))
            let keyIdAfterFirst = defaults.string(forKey: Self.keyIdStorageKey)
            #expect(keyIdAfterFirst == ScriptedAppAttestService.generatedKeyId)
            #expect(
                defaults.string(forKey: Self.attestedKeyIdStorageKey)
                    == ScriptedAppAttestService.generatedKeyId
            )

            // A second attestation is an ordinary call, because a server
            // challenge is single-use. Apple answers `invalidKey` for it.
            await #expect(throws: AttestationError.self) {
                _ = try await adapter.attest(challenge: Data([0x03]), deviceId: Data([0x02]))
            }

            // That second call must leave one key alive: discarding it here
            // burns one Secure Enclave key per two `attest` calls, and leaves
            // `assertRequest` throwing `keyNotFound` over a key that still
            // exists.
            #expect(defaults.string(forKey: Self.keyIdStorageKey) == keyIdAfterFirst)
            #expect(service.keyGenerationCount == 1)
            let bytes = try await adapter.assertRequest(requestHash: Data(repeating: 0xAB, count: 32))
            #expect(bytes == assertion)
        }

        @Test("an assertion after a failed attestation keeps its key for a retry")
        func assertionAfterFailedAttestationKeepsKey() async throws {
            let defaults = InMemoryUserDefaults()
            let attestation = Data([0x04, 0x05])
            let service = ScriptedAppAttestService(
                attestScript: [
                    .failure(ScriptedAppAttestService.serverUnavailableError),
                    .success(attestation)
                ],
                assertScript: [.failure(ScriptedAppAttestService.invalidKeyError)]
            )
            let adapter = AppleDeviceAttestation(
                appId: CBORFixture.appId,
                service: service,
                defaults: defaults
            )

            // A first attestation generates a key and then fails to reach
            // Apple, so that key stays stored and unattested.
            _ = try? await adapter.attest(challenge: Data([0x01]), deviceId: Data([0x02]))
            #expect(
                defaults.string(forKey: Self.keyIdStorageKey)
                    == ScriptedAppAttestService.generatedKeyId
            )

            // An assertion before that retry hits an unattested key. Discarding
            // that key here throws away what a retry needs.
            _ = try? await adapter.assertRequest(requestHash: Data(repeating: 0xAB, count: 32))
            #expect(
                defaults.string(forKey: Self.keyIdStorageKey)
                    == ScriptedAppAttestService.generatedKeyId
            )

            // Retrying that attestation with that same key succeeds.
            let bytes = try await adapter.attest(challenge: Data([0x01]), deviceId: Data([0x02]))
            #expect(bytes == attestation)
            #expect(service.keyGenerationCount == 1)
        }

        @Test("a freshly generated key carries no attestation from a key it replaced")
        func generatedKeyCarriesNoStaleAttestation() async {
            let defaults = InMemoryUserDefaults()
            // A record left by a previous key, which a generated key must not
            // inherit: inheriting it would classify a rejected key as already
            // attested and keep a dead key ID forever.
            defaults.set("previous-key-id", forKey: Self.attestedKeyIdStorageKey)
            let adapter = AppleDeviceAttestation(
                appId: CBORFixture.appId,
                service: ScriptedAppAttestService(),
                defaults: defaults
            )

            _ = try? await adapter.attest(challenge: Data([0x01]), deviceId: Data([0x02]))

            #expect(defaults.string(forKey: Self.attestedKeyIdStorageKey) == nil)
            #expect(defaults.string(forKey: Self.keyIdStorageKey) == nil)
        }
    }

    // MARK: - verify(token:) acceptance tests

    struct AppAttestVerifyAcceptanceTests {
        /// Every `verify` case needs an adapter instance; a service double
        /// never runs, because `verify` consults no service.
        private func makeAdapter() -> AttestationHarness {
            makeUnsupportedAdapter()
        }

        @Test("verify accepts an attestation object satisfying all four clauses")
        func verifyAcceptsConformantObject() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            #expect(adapter.verify(token: CBORFixture.attestationObject()) == true)
        }

        @Test("verify accepts a development AAGUID clause 4 names alongside a production one")
        func verifyAcceptsDevelopmentAaguid() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.byteString(
                    CBORFixture.authenticatorData(aaguid: CBORFixture.developmentAaguid)
                )
            )
            #expect(adapter.verify(token: token) == true)
        }

        @Test("verify accepts an x5c array carrying more than two certificates clause 3 requires")
        func verifyAcceptsThreeCertificates() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.attestationStatement(
                    certificates: [
                        CBORFixture.credentialCertificate,
                        CBORFixture.intermediateCertificate,
                        CBORFixture.credentialCertificate
                    ]
                )
            )
            #expect(adapter.verify(token: token) == true)
        }

        @Test("verify accepts authenticator data longer than an 87-byte floor")
        func verifyAcceptsLongAuthenticatorData() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let extended = CBORFixture.authenticatorData() + [UInt8](repeating: 0x77, count: 40)
            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.byteString(extended)
            )
            #expect(adapter.verify(token: token) == true)
        }

        @Test("verify constrains neither a flags byte nor a sign counter")
        func verifyIgnoresFlagsAndSignCounter() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.byteString(
                    CBORFixture.authenticatorData(
                        flags: 0x00,
                        signCounter: [0xFF, 0xFF, 0xFF, 0xFF]
                    )
                )
            )
            #expect(adapter.verify(token: token) == true)
        }

        @Test("verify rejects a token an adapter for another App ID accepts")
        func verifyBindsToItsOwnAppId() {
            let harness = makeAdapter()

            let foreignAdapter = AppleDeviceAttestation(
                appId: CBORFixture.foreignAppId,
                service: UnsupportedAppAttestService(),
                defaults: InMemoryUserDefaults()
            )

            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.byteString(
                    CBORFixture.authenticatorData(appId: CBORFixture.foreignAppId)
                )
            )
            #expect(foreignAdapter.verify(token: token) == true)
            #expect(harness.adapter.verify(token: token) == false)
        }
    }

    // MARK: - verify(token:) rejection tests, clauses 1 and 2

    struct AppleDeviceAttestationVerifyTests {
        /// Every `verify` case needs an adapter instance; a service double
        /// never runs, because `verify` consults no service.
        private func makeAdapter() -> AttestationHarness {
            makeUnsupportedAdapter()
        }

        @Test("verify rejects an empty token")
        func verifyRejectsEmpty() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            #expect(adapter.verify(token: Data()) == false)
        }

        @Test("verify rejects a synthetic software token this adapter once minted")
        func verifyRejectsSyntheticSoftwareToken() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            // Before a fail-closed rewrite landed, `attest` minted this shape on
            // an unsupported device and `verify` returned true for it.
            let legacyToken = Data("software-attestation-\(UUID().uuidString)".utf8)
            #expect(adapter.verify(token: legacyToken) == false)
        }

        @Test("verify rejects arbitrary non-CBOR bytes")
        func verifyRejectsArbitraryBytes() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            #expect(adapter.verify(token: Data(repeating: 0xFF, count: 256)) == false)
            #expect(adapter.verify(token: Data("not an attestation".utf8)) == false)
        }

        @Test("verify rejects an attestation object whose fmt is not apple-appattest")
        func verifyRejectsForeignFormat() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(format: "packed")
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an attestation object carrying an unknown key")
        func verifyRejectsUnknownKey() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(extraKey: "smuggled")
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects a truncated attestation object")
        func verifyRejectsTruncatedObject() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let complete = CBORFixture.attestationObject()
            let truncated = complete.prefix(complete.count - 5)
            #expect(adapter.verify(token: Data(truncated)) == false)
        }

        @Test("verify rejects an attestation object followed by trailing bytes")
        func verifyRejectsTrailingBytes() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var token = CBORFixture.attestationObject()
            token.append(contentsOf: [0x00, 0x01])
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects a top-level item that is not a map")
        func verifyRejectsNonMapTopLevel() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let arrayToken = Data(CBORFixture.arrayHeader(0))
            #expect(adapter.verify(token: arrayToken) == false)
        }

        @Test("verify rejects an array carrying six items a conformant map carries")
        func verifyRejectsArrayOfKeyValuePairs() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            // An array head declaring three elements carries an argument of
            // three, and six items follow it: three keys and three values a
            // conformant map carries, in that order. A reader that ignored
            // major types would accept this token, so a major-type check is
            // what separates it from that map.
            var out = CBORFixture.arrayHeader(3)
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += CBORFixture.text("attStmt") + CBORFixture.attestationStatement()
            out += CBORFixture.text("authData")
                + CBORFixture.byteString(CBORFixture.authenticatorData())
            #expect(adapter.verify(token: Data(out)) == false)
        }

        @Test("verify rejects an indefinite-length map")
        func verifyRejectsIndefiniteLengthMap() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            // 0xBF opens an indefinite-length map; 0xFF closes it. Apple emits
            // definite lengths only, so this adapter rejects such an encoding.
            var out: [UInt8] = [0xBF]
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += [0xFF]
            #expect(adapter.verify(token: Data(out)) == false)
        }

        @Test("verify rejects a map that declares more entries than its bytes hold")
        func verifyRejectsOverlongMapCount() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            // A map header claiming 65535 entries followed by two bytes.
            let token = Data(CBORFixture.head(major: 5, argument: 0xFFFF) + [0x61, 0x66])
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an attestation object missing a required key")
        func verifyRejectsMissingKey() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var out = CBORFixture.mapHeader(2)
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += CBORFixture.text("attStmt") + CBORFixture.attestationStatement()
            #expect(adapter.verify(token: Data(out)) == false)
        }

        @Test("verify rejects a four-entry object that repeats a key")
        func verifyRejectsDuplicateKeyInFourEntries() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var out = CBORFixture.mapHeader(4)
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += CBORFixture.text("attStmt") + CBORFixture.attestationStatement()
            out += CBORFixture.text("authData")
                + CBORFixture.byteString(CBORFixture.authenticatorData())
            #expect(adapter.verify(token: Data(out)) == false)
        }

        @Test("verify rejects a three-entry object that repeats a key and omits authData")
        func verifyRejectsDuplicateKeyInThreeEntries() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            // An entry count of three passes a count comparison, so only a
            // duplicate-key check rejects this token. Dropping that check would
            // make `verify` accept an object carrying no authenticator data.
            var out = CBORFixture.mapHeader(3)
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += CBORFixture.text("attStmt") + CBORFixture.attestationStatement()
            #expect(adapter.verify(token: Data(out)) == false)
        }

        @Test("verify rejects a three-entry object whose third key is unknown")
        func verifyRejectsUnknownKeyInThreeEntries() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var out = CBORFixture.mapHeader(3)
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += CBORFixture.text("attStmt") + CBORFixture.attestationStatement()
            out += CBORFixture.text("smuggled")
                + CBORFixture.byteString(CBORFixture.authenticatorData())
            #expect(adapter.verify(token: Data(out)) == false)
        }

        @Test("verify rejects an fmt value that is not a text string")
        func verifyRejectsNonTextFormat() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var out = CBORFixture.mapHeader(3)
            out += CBORFixture.text("fmt")
                + CBORFixture.byteString([UInt8](CBORFixture.appleFormat.utf8))
            out += CBORFixture.text("attStmt") + CBORFixture.attestationStatement()
            out += CBORFixture.text("authData")
                + CBORFixture.byteString(CBORFixture.authenticatorData())
            #expect(adapter.verify(token: Data(out)) == false)
        }

        @Test("verify rejects a map header declaring four billion entries")
        func verifyRejectsUnsatisfiableMapCount() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            // 0xBA opens a map whose entry count arrives as a four-byte
            // argument. This case pins two properties: `verify` rejects such a
            // token, and it returns rather than iterating a declared count that
            // its input cannot hold.
            let token = Data([0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0x61, 0x66])
            #expect(adapter.verify(token: token) == false)
        }
    }

    // MARK: - verify(token:) rejection tests, clause 3 (attStmt)

    struct AppAttestStatementClauseTests {
        private func makeAdapter() -> AttestationHarness {
            makeUnsupportedAdapter()
        }

        @Test("verify rejects an attestation object whose attStmt is not a map")
        func verifyRejectsNonMapAttestationStatement() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.byteString([0x01, 0x02])
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an empty attStmt map")
        func verifyRejectsEmptyAttestationStatement() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.mapHeader(0)
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an attStmt carrying a key outside x5c and receipt")
        func verifyRejectsExtraAttestationStatementKey() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var statement = CBORFixture.mapHeader(3)
            statement += CBORFixture.text("x5c")
            statement += CBORFixture.arrayHeader(2)
            statement += CBORFixture.byteString(CBORFixture.credentialCertificate)
            statement += CBORFixture.byteString(CBORFixture.intermediateCertificate)
            statement += CBORFixture.text("receipt") + CBORFixture.byteString([0x0A])
            statement += CBORFixture.text("smuggled") + CBORFixture.byteString([0x0B])

            let token = CBORFixture.attestationObject(attestationStatementValue: statement)
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an attStmt missing receipt")
        func verifyRejectsAttestationStatementMissingReceipt() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var statement = CBORFixture.mapHeader(1)
            statement += CBORFixture.text("x5c")
            statement += CBORFixture.arrayHeader(2)
            statement += CBORFixture.byteString(CBORFixture.credentialCertificate)
            statement += CBORFixture.byteString(CBORFixture.intermediateCertificate)

            let token = CBORFixture.attestationObject(attestationStatementValue: statement)
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an attStmt that repeats x5c")
        func verifyRejectsDuplicateAttestationStatementKey() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var statement = CBORFixture.mapHeader(2)
            for _ in 0 ..< 2 {
                statement += CBORFixture.text("x5c")
                statement += CBORFixture.arrayHeader(2)
                statement += CBORFixture.byteString(CBORFixture.credentialCertificate)
                statement += CBORFixture.byteString(CBORFixture.intermediateCertificate)
            }

            let token = CBORFixture.attestationObject(attestationStatementValue: statement)
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an x5c array holding one certificate")
        func verifyRejectsSingleCertificateChain() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.attestationStatement(
                    certificates: [CBORFixture.credentialCertificate]
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an x5c element that does not parse as a DER X.509 certificate")
        func verifyRejectsNonCertificateChainElement() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            // 300 bytes of DER-shaped filler: a SEQUENCE header over payload
            // that carries no X.509 structure.
            let notACertificate: [UInt8] = [0x30, 0x82, 0x01, 0x2C] + [UInt8](repeating: 0x41, count: 300)
            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.attestationStatement(
                    certificates: [CBORFixture.credentialCertificate, notACertificate]
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an x5c that is not an array")
        func verifyRejectsNonArrayCertificateChain() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var statement = CBORFixture.mapHeader(2)
            statement += CBORFixture.text("x5c")
            statement += CBORFixture.byteString(CBORFixture.credentialCertificate)
            statement += CBORFixture.text("receipt") + CBORFixture.byteString([0x0A])

            let token = CBORFixture.attestationObject(attestationStatementValue: statement)
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an x5c map carrying two certificates as one key and one value")
        func verifyRejectsMapCertificateChain() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            // A map head declaring two entries carries an argument of two, so a
            // reader that ignored major types would read both certificates from
            // it exactly as it reads them from a two-element array head. Only a
            // major-type check separates this token from a conformant one.
            var statement = CBORFixture.mapHeader(2)
            statement += CBORFixture.text("x5c")
            statement += CBORFixture.mapHeader(2)
            statement += CBORFixture.byteString(CBORFixture.credentialCertificate)
            statement += CBORFixture.byteString(CBORFixture.intermediateCertificate)
            statement += CBORFixture.text("receipt") + CBORFixture.byteString([0x0A])

            let token = CBORFixture.attestationObject(attestationStatementValue: statement)
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an x5c that repeats one self-signed certificate twice")
        func verifyRejectsDuplicatedCertificate() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            // A self-signed certificate names itself in its own issuer field,
            // so a pair of copies satisfies issuer-to-subject equality without
            // carrying two certificates. Clause 3 assigns two certificates.
            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.attestationStatement(
                    certificates: [
                        CBORFixture.intermediateCertificate,
                        CBORFixture.intermediateCertificate
                    ]
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an x5c whose third element does not parse as a certificate")
        func verifyRejectsNonCertificateBeyondPositionOne() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let notACertificate: [UInt8] = [0x30, 0x82, 0x01, 0x2C]
                + [UInt8](repeating: 0x41, count: 300)
            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.attestationStatement(
                    certificates: [
                        CBORFixture.credentialCertificate,
                        CBORFixture.intermediateCertificate,
                        notACertificate
                    ]
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects a credential certificate whose issuer name resists normalization")
        func verifyRejectsUnnormalizableIssuerName() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.attestationStatement(
                    certificates: [
                        CBORFixture.retaggedIssuerCertificate,
                        CBORFixture.intermediateCertificate
                    ]
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an x5c whose element 0 names no issuer in element 1")
        func verifyRejectsUnlinkedCertificateChain() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.attestationStatement(
                    certificates: [
                        CBORFixture.unrelatedCertificate,
                        CBORFixture.intermediateCertificate
                    ]
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an x5c that carries a credential certificate after its issuer")
        func verifyRejectsReversedCertificateChain() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.attestationStatement(
                    certificates: [
                        CBORFixture.intermediateCertificate,
                        CBORFixture.credentialCertificate
                    ]
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an x5c element that is not a byte string")
        func verifyRejectsNonByteStringChainElement() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var statement = CBORFixture.mapHeader(2)
            statement += CBORFixture.text("x5c")
            statement += CBORFixture.arrayHeader(2)
            statement += CBORFixture.byteString(CBORFixture.credentialCertificate)
            statement += CBORFixture.text("a certificate as text")
            statement += CBORFixture.text("receipt") + CBORFixture.byteString([0x0A])

            let token = CBORFixture.attestationObject(attestationStatementValue: statement)
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects a two-entry attStmt whose keys are both unknown")
        func verifyRejectsTwoUnknownStatementKeys() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var statement = CBORFixture.mapHeader(2)
            statement += CBORFixture.text("chain") + CBORFixture.byteString([0x0A])
            statement += CBORFixture.text("proof") + CBORFixture.byteString([0x0B])

            let token = CBORFixture.attestationObject(attestationStatementValue: statement)
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects a receipt that is not a byte string")
        func verifyRejectsNonByteStringReceipt() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            var statement = CBORFixture.mapHeader(2)
            statement += CBORFixture.text("x5c")
            statement += CBORFixture.arrayHeader(2)
            statement += CBORFixture.byteString(CBORFixture.credentialCertificate)
            statement += CBORFixture.byteString(CBORFixture.intermediateCertificate)
            statement += CBORFixture.text("receipt") + CBORFixture.text("not bytes")

            let token = CBORFixture.attestationObject(attestationStatementValue: statement)
            #expect(adapter.verify(token: token) == false)
        }
    }

    // MARK: - verify(token:) rejection tests, clause 4 (authData)

    struct AppAttestAuthDataClauseTests {
        private func makeAdapter() -> AttestationHarness {
            makeUnsupportedAdapter()
        }

        @Test("verify rejects authenticator data of 37 bytes")
        func verifyRejectsThirtySevenByteAuthenticatorData() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let short = CBORFixture.relyingPartyIdHash(of: CBORFixture.appId)
                + [0x40] + [0x00, 0x00, 0x00, 0x01]
            #expect(short.count == 37)
            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.byteString(short)
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects authenticator data one byte below an 87-byte floor")
        func verifyRejectsEightySixByteAuthenticatorData() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let short = Array(CBORFixture.authenticatorData().prefix(86))
            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.byteString(short)
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects a relying-party ID hash belonging to another App ID")
        func verifyRejectsForeignRelyingPartyIdHash() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.byteString(
                    CBORFixture.authenticatorData(appId: CBORFixture.foreignAppId)
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects 87 bytes of authenticator data that carry no App Attest fields")
        func verifyRejectsUnstructuredAuthenticatorData() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.byteString(
                    [UInt8](repeating: 0x11, count: 87)
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an AAGUID that is neither App Attest value")
        func verifyRejectsForeignAaguid() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.byteString(
                    CBORFixture.authenticatorData(
                        aaguid: [UInt8]("webauthn.io\u{0}\u{0}\u{0}\u{0}\u{0}".utf8)
                    )
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an AAGUID that pads appattest with bytes other than zero")
        func verifyRejectsWronglyPaddedAaguid() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let padded = [UInt8]("appattest".utf8) + [UInt8](repeating: 0x20, count: 7)
            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.byteString(
                    CBORFixture.authenticatorData(aaguid: padded)
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects a credential-ID length other than 0x0020")
        func verifyRejectsWrongCredentialIdLength() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.byteString(
                    CBORFixture.authenticatorData(credentialIdLength: [0x00, 0x40])
                )
            )
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects authenticator data that is not a byte string")
        func verifyRejectsNonByteStringAuthenticatorData() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(
                authenticatorDataValue: CBORFixture.text("authenticator data as text")
            )
            #expect(adapter.verify(token: token) == false)
        }
    }

#endif // os(iOS) || os(macOS)
