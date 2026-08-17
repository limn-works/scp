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
// 4. Concurrent calls reach Apple's App Attest service one at a time, and a
//    second `attest` therefore keeps the key a first `attest` got attested
//    rather than reading a stale attestation record and discarding that key.
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
//    string. `readCertificateChain` evaluates those certificates as a
//    certification path anchored at Apple's App Attest root certificate, and
//    requires that path to start with element 0 and element 1.
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
    import Security
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

    /// A `DCAppAttestService` that answers each call after a delay and records
    /// how many calls were outstanding at once.
    ///
    /// Apple's App Attest service answers `attestKey` and `generateAssertion`
    /// over a round trip to Apple, so two calls a caller starts close together
    /// are outstanding at once unless something serializes them. Answering
    /// after a delay reproduces that window, and counting outstanding calls is
    /// what lets a case state whether `AppleDeviceAttestation` closed it.
    private final class OverlapDetectingAppAttestService: DCAppAttestService, @unchecked Sendable {
        /// A key ID `generateKey` hands back.
        static let generatedKeyId = "overlap-detecting-key-id"

        /// What Apple returns for each of three `DCError.invalidKey` conditions.
        static let invalidKeyError = NSError(
            domain: DCErrorDomain,
            code: DCError.invalidKey.rawValue,
            userInfo: nil
        )

        /// One scripted answer: what to hand back, and how long to wait first.
        struct Answer {
            let result: Result<Data, Error>
            let delay: TimeInterval
        }

        private let lock = NSLock()
        private var attestScript: [Answer]
        private var assertScript: [Answer]
        private var outstandingCalls = 0
        private var peakOutstandingCalls = 0

        /// Most calls this double had outstanding at one moment.
        var peakConcurrency: Int {
            lock.withLock { peakOutstandingCalls }
        }

        init(attestScript: [Answer], assertScript: [Answer]) {
            self.attestScript = attestScript
            self.assertScript = assertScript
            super.init()
        }

        override var isSupported: Bool {
            true
        }

        override func generateKey(completionHandler: @escaping (String?, Error?) -> Void) {
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

        /// Take a script's next answer, keeping its last answer in place, and
        /// deliver it after that answer's delay.
        private func answer(
            from script: ReferenceWritableKeyPath<OverlapDetectingAppAttestService, [Answer]>,
            to completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            let next: Answer = lock.withLock {
                outstandingCalls += 1
                peakOutstandingCalls = max(peakOutstandingCalls, outstandingCalls)
                guard let first = self[keyPath: script].first else {
                    return Answer(result: .failure(Self.invalidKeyError), delay: 0)
                }
                if self[keyPath: script].count > 1 {
                    self[keyPath: script].removeFirst()
                }
                return first
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + next.delay) { [self] in
                lock.withLock { outstandingCalls -= 1 }
                switch next.result {
                case let .success(data):
                    completionHandler(data, nil)
                case let .failure(error):
                    completionHandler(nil, error)
                }
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

        /// A self-signed P-256 root CA certificate in DER form, standing in for
        /// Apple's App Attest root certificate.
        ///
        /// Clause 3 requires an `x5c` chain to terminate at Apple's App Attest
        /// root, and Apple holds that root's private key, so no test can build
        /// a chain Apple signed. Every `verify` case that expects `true`
        /// therefore hands `AppleDeviceAttestation` this certificate as its one
        /// anchor and builds chains beneath it. Cases in
        /// `AppAttestAppleAnchorTests` hand it no anchor, which binds it to
        /// Apple's root and pins what a production caller gets.
        static let testRootCertificate = der(
            """
            MIIBsDCCAVegAwIBAgIUEpz+gnPq8BUXG9o06kMmMqbyqtswCgYIKoZIzj0EAwIwJTEjMCEGA1UEAw
            waU0NQIEFwcEF0dGVzdCBUZXN0IFJvb3QgQ0EwIBcNMjYwODE3MDM0NjMwWhgPMjEyNjA3MjQwMzQ2
            MzBaMCUxIzAhBgNVBAMMGlNDUCBBcHBBdHRlc3QgVGVzdCBSb290IENBMFkwEwYHKoZIzj0CAQYIKo
            ZIzj0DAQcDQgAEZfm4GNde5LEPL6FZhUdmh6abr2NH+TB37bVtjw5uBM68LGSnS1P+IBzVkOY8wgHo
            gu3E73x2NO8fe84Xsu/WQKNjMGEwHQYDVR0OBBYEFK0nJNceI7oHbymj/JEP7Codr7uTMB8GA1UdIw
            QYMBaAFK0nJNceI7oHbymj/JEP7Codr7uTMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEG
            MAoGCCqGSM49BAMCA0cAMEQCID9beOLHDTp1d83GLcWKVa3DOgnZ4RTvDHvKHyZxsixrAiBLPxfsXW
            GkerYZlDr8YdZl4SGnyB17rOyJ3dsk8FRq5A==
            """
        )

        /// A P-256 certificate in DER form, standing in for an App Attest
        /// credential certificate. `intermediateCertificate` issued it, and
        /// `testRootCertificate` issued that one, so element 0 of `x5c` heads a
        /// path terminating at the anchor these cases inject.
        static let credentialCertificate = der(
            """
            MIIBtzCCAVygAwIBAgIUKzq+jlxAiO0QFWbiw3dcNbYq/QkwCgYIKoZIzj0EAwIwKjEoMCYGA1UEAw
            wfU0NQIEFwcEF0dGVzdCBUZXN0IEludGVybWVkaWF0ZTAgFw0yNjA4MTcwMzQ2MzdaGA8yMTI2MDcy
            NDAzNDYzN1owKDEmMCQGA1UEAwwdU0NQIEFwcEF0dGVzdCBUZXN0IENyZWRlbnRpYWwwWTATBgcqhk
            jOPQIBBggqhkjOPQMBBwNCAAS/MYXK3xIppZN/w0mpygVLeAawSBwQXTNJMCnjun6KXebSEX32+Tq1
            ADYk97sKgiuBcZxYcWEIUh1jenJnIqQQo2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgD
            AdBgNVHQ4EFgQU+jxydDE6rguMUTwVLqPfxzU557cwHwYDVR0jBBgwFoAUb73SBIsV2BQv1QeKzoiA
            TKBeYsUwCgYIKoZIzj0EAwIDSQAwRgIhAOpNoqafHHTYjXPHHM6kVI6Kfg0aHqOy3z0KkimW3Z55Ai
            EAhMQon7aDotLnphdZ3IXjwxRmb4DoVbbM1qWThgFQKME=
            """
        )

        /// A P-256 CA certificate in DER form, standing in for an Apple App
        /// Attest intermediate certificate. `testRootCertificate` issued it,
        /// and it issued `credentialCertificate`.
        static let intermediateCertificate = der(
            """
            MIIBuDCCAV+gAwIBAgIUS9iGZBUof14MT+Byg6YxKYYX18UwCgYIKoZIzj0EAwIwJTEjMCEGA1UEAw
            waU0NQIEFwcEF0dGVzdCBUZXN0IFJvb3QgQ0EwIBcNMjYwODE3MDM0NjM0WhgPMjEyNjA3MjQwMzQ2
            MzRaMCoxKDAmBgNVBAMMH1NDUCBBcHBBdHRlc3QgVGVzdCBJbnRlcm1lZGlhdGUwWTATBgcqhkjOPQ
            IBBggqhkjOPQMBBwNCAARKVbivGu3og+j+DO971GB6hWFyqXVXqXXItUwjlW6eluk89Hajxk3BZVxV
            x/ypx0jqmzaIxLjvD1hWwYmlKzUZo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAw
            IBBjAdBgNVHQ4EFgQUb73SBIsV2BQv1QeKzoiATKBeYsUwHwYDVR0jBBgwFoAUrSck1x4jugdvKaP8
            kQ/sKh2vu5MwCgYIKoZIzj0EAwIDRwAwRAIgTZ4ov4tnBH4JdHTIKA2g9T/OM8GtTV/bD1ktQFLJNS
            ACIEc4Lq1tDjauQaxKqihn7/sQsmaA6qrgihEhqvdthTna
            """
        )

        /// A second credential certificate in DER form, which
        /// `rotatedIntermediateCertificate` issued.
        ///
        /// Apple replaces its App Attest intermediate certificate on its own
        /// schedule. This pair, sharing `testRootCertificate` with
        /// `credentialCertificate` and carrying a different subject name, a
        /// different serial number, and a different public key, stands for a
        /// chain Apple signed after such a replacement.
        static let rotatedCredentialCertificate = der(
            """
            MIIBvDCCAWKgAwIBAgIUWMSrcbu2EaYH4fuYy9PvTitAYg8wCgYIKoZIzj0EAwIwLTErMCkGA1UEAw
            wiU0NQIEFwcEF0dGVzdCBUZXN0IEludGVybWVkaWF0ZSBHMjAgFw0yNjA4MTcwMzQ3MDBaGA8yMTI2
            MDcyNDAzNDcwMFowKzEpMCcGA1UEAwwgU0NQIEFwcEF0dGVzdCBUZXN0IENyZWRlbnRpYWwgRzIwWT
            ATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATM8mH4eqBAfpU65IrimyCz7IDIHOYn+2lEiYQYG3eGCZMO
            EjhE6lzCxuYek8W33xJO+QOtDZc2cuSMQiQ3QwVco2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/w
            QEAwIHgDAdBgNVHQ4EFgQUw+TvHe0B8vDvprIoeRT+Ztjy0NwwHwYDVR0jBBgwFoAUpAPjjE32T3ap
            bnttMXmv+kLPvicwCgYIKoZIzj0EAwIDSAAwRQIhAM5eWObLS8wK6QmYbKQOeQcROqw2hPsc8oicCq
            Cx4fw3AiBSOalFR/JR+ogpAIcx94iyNZj+8ib+LVVd0HTq46CyQQ==
            """
        )

        /// A second intermediate certificate in DER form, which
        /// `testRootCertificate` issued and which issued
        /// `rotatedCredentialCertificate`.
        static let rotatedIntermediateCertificate = der(
            """
            MIIBvDCCAWKgAwIBAgIUS9iGZBUof14MT+Byg6YxKYYX18YwCgYIKoZIzj0EAwIwJTEjMCEGA1UEAw
            waU0NQIEFwcEF0dGVzdCBUZXN0IFJvb3QgQ0EwIBcNMjYwODE3MDM0NzAwWhgPMjEyNjA3MjQwMzQ3
            MDBaMC0xKzApBgNVBAMMIlNDUCBBcHBBdHRlc3QgVGVzdCBJbnRlcm1lZGlhdGUgRzIwWTATBgcqhk
            jOPQIBBggqhkjOPQMBBwNCAAQO7KxZFjoiqXPP22ENJJLwM6oklMRuodZ45Bq6mhnu/4+KyJtYVoLX
            LAqPUhDSM1HwxvBXx9vzuPg/j9hFGuuMo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/w
            QEAwIBBjAdBgNVHQ4EFgQUpAPjjE32T3apbnttMXmv+kLPvicwHwYDVR0jBBgwFoAUrSck1x4jugdv
            KaP8kQ/sKh2vu5MwCgYIKoZIzj0EAwIDSAAwRQIhAOfOe+roM7/b7eUvXSHmJEZusAmAzNPNUTYQo0
            wkn7rLAiAWvBhfNJDwjU9x8GGTy5WU2TOfq6611QL4rCKqcIRpDQ==
            """
        )

        /// A credential certificate in DER form that a certification authority
        /// outside this test PKI issued.
        ///
        /// `rogueRootCertificate` issued it, so the pair forms a complete,
        /// internally valid, self-signed chain, and clause 3 rejects it because
        /// that chain terminates at neither Apple's App Attest root nor
        /// `testRootCertificate`.
        static let rogueCredentialCertificate = der(
            """
            MIIBrDCCAVGgAwIBAgIUWnuEIm3DdOZvuwgScd3qhoZndO4wCgYIKoZIzj0EAwIwIjEgMB4GA1UEAw
            wXUm9ndWUgQXBwQXR0ZXN0IFJvb3QgQ0EwIBcNMjYwODE3MDM0NzA2WhgPMjEyNjA3MjQwMzQ3MDZa
            MCUxIzAhBgNVBAMMGlJvZ3VlIEFwcEF0dGVzdCBDcmVkZW50aWFsMFkwEwYHKoZIzj0CAQYIKoZIzj
            0DAQcDQgAEpnFWKAT1yzc2r6taBOn1g4Xj01CUEQOkugC8TQuBYS8KWiB14AiR+oYZeGRiUIm957WK
            59bG60zZc/V/TdgNDaNgMF4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFG
            XWGCyk8Nj5pYzkGhg1pWLXCayuMB8GA1UdIwQYMBaAFGMTcDZcysG7zt/0h9rfSzJ9O3d5MAoGCCqG
            SM49BAMCA0kAMEYCIQDPsKOd1H2j6e1Fq0rtVGYmfwNyKwNe/R8bxn3QYxLyUAIhAJ9zIpumNczT+y
            1m2P7qRmVXjfJwDb9ohQKng4BA/Wkg
            """
        )

        /// A self-signed root CA certificate in DER form that issued
        /// `rogueCredentialCertificate`. Anyone can mint this pair with
        /// `openssl`, which is what makes a chain reaching no pinned anchor
        /// worthless.
        static let rogueRootCertificate = der(
            """
            MIIBrDCCAVGgAwIBAgIUOSgC3kN3IKkt3Rlv1JzWQGvU1pswCgYIKoZIzj0EAwIwIjEgMB4GA1UEAw
            wXUm9ndWUgQXBwQXR0ZXN0IFJvb3QgQ0EwIBcNMjYwODE3MDM0NzA2WhgPMjEyNjA3MjQwMzQ3MDZa
            MCIxIDAeBgNVBAMMF1JvZ3VlIEFwcEF0dGVzdCBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQ
            cDQgAEG62S2jEXFb3O79kahwU/Iu/hY4YcU6HM2qFv0SQ3Cqh6B+mDjQF8ewEd4EWzsEQ7KUb8hlGu
            1qgQ/VolvPA3n6NjMGEwHQYDVR0OBBYEFGMTcDZcysG7zt/0h9rfSzJ9O3d5MB8GA1UdIwQYMBaAFG
            MTcDZcysG7zt/0h9rfSzJ9O3d5MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqG
            SM49BAMCA0kAMEYCIQDpgHs71+2st0jWJlKyZtyqks2IHcPpsOJYqS8Yqt39sgIhAIetDP+DK0CCZb
            uzO/fxBbACNaJvpEmdgzzHeYcxLkjs
            """
        )

        /// `credentialCertificate` with one byte changed: its issuer name's
        /// first `RelativeDistinguishedName` carries tag `SEQUENCE` where X.501
        /// requires `SET`. Every enclosing length stays valid, so
        /// `SecCertificateCreateWithData` still parses it, while the issuer
        /// name it presents matches no certificate's subject name, so no path
        /// builds from it.
        static let retaggedIssuerCertificate = der(
            """
            MIIBtzCCAVygAwIBAgIUKzq+jlxAiO0QFWbiw3dcNbYq/QkwCgYIKoZIzj0EAwIwKjAoMCYGA1UEAw
            wfU0NQIEFwcEF0dGVzdCBUZXN0IEludGVybWVkaWF0ZTAgFw0yNjA4MTcwMzQ2MzdaGA8yMTI2MDcy
            NDAzNDYzN1owKDEmMCQGA1UEAwwdU0NQIEFwcEF0dGVzdCBUZXN0IENyZWRlbnRpYWwwWTATBgcqhk
            jOPQIBBggqhkjOPQMBBwNCAAS/MYXK3xIppZN/w0mpygVLeAawSBwQXTNJMCnjun6KXebSEX32+Tq1
            ADYk97sKgiuBcZxYcWEIUh1jenJnIqQQo2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgD
            AdBgNVHQ4EFgQU+jxydDE6rguMUTwVLqPfxzU557cwHwYDVR0jBBgwFoAUb73SBIsV2BQv1QeKzoiA
            TKBeYsUwCgYIKoZIzj0EAwIDSQAwRgIhAOpNoqafHHTYjXPHHM6kVI6Kfg0aHqOy3z0KkimW3Z55Ai
            EAhMQon7aDotLnphdZ3IXjwxRmb4DoVbbM1qWThgFQKME=
            """
        )

        /// A self-signed P-256 certificate in DER form that issued nothing and
        /// that `intermediateCertificate` did not issue. Clause 3 rejects it in
        /// either position of a two-element `x5c`.
        static let unrelatedCertificate = der(
            """
            MIIBpTCCAUugAwIBAgIUSLm1aEHWNWGCQZ8CCnQQyAQRTkowCgYIKoZIzj0EAwIwJzElMCMGA1UEAw
            wcU0NQIEFwcEF0dGVzdCBUZXN0IFVucmVsYXRlZDAgFw0yNjA4MTcwMzQ3MDZaGA8yMTI2MDcyNDAz
            NDcwNlowJzElMCMGA1UEAwwcU0NQIEFwcEF0dGVzdCBUZXN0IFVucmVsYXRlZDBZMBMGByqGSM49Ag
            EGCCqGSM49AwEHA0IABFhAjHcHSmkbzTYFYLfMK0j4F3Wp8S3nB47IjZ+uOuuJru712fx5Vij0KTKZ
            qFZZIVXzeQEBUgOTsdysUyEpAJyjUzBRMB0GA1UdDgQWBBQ4kKM+o13HHCOPHr6vnc//zo/+dDAfBg
            NVHSMEGDAWgBQ4kKM+o13HHCOPHr6vnc//zo/+dDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMC
            A0gAMEUCIQDFwXKEgRsS9bP37jI/0p+CYo22oSMQF8dcUDFAF1c7ugIgZ2+K9jRZr8bRQy+bx3Vyjb
            x3j0ChnPjemSO+gTZcz9Q=
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

        /// `testRootCertificate` as one anchor array, which every `verify` case
        /// expecting `true` injects into `AppleDeviceAttestation`.
        static func testAnchors() -> [SecCertificate] {
            guard let certificate = SecCertificateCreateWithData(
                nil,
                Data(testRootCertificate) as CFData
            ) else { return [] }
            return [certificate]
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
    ///
    /// - Parameter anchorCertificates: Certificates `verify(token:)` anchors an
    ///   `x5c` chain at. This defaults to `CBORFixture.testAnchors()`, because
    ///   Apple holds its App Attest root's private key and no test can build a
    ///   chain that root signed. `makeAppleAnchoredAdapter()` builds the
    ///   adapter a production caller gets.
    private func makeUnsupportedAdapter(
        anchorCertificates: [SecCertificate] = CBORFixture.testAnchors()
    ) -> AttestationHarness {
        let defaults = InMemoryUserDefaults()
        let adapter = AppleDeviceAttestation(
            appId: CBORFixture.appId,
            service: UnsupportedAppAttestService(),
            defaults: defaults,
            anchorCertificates: anchorCertificates
        )
        return AttestationHarness(adapter: adapter, defaults: defaults)
    }

    /// Build an adapter carrying whichever anchor `AppleDeviceAttestation`
    /// binds when a caller passes none, which is Apple's App Attest root
    /// certificate.
    private func makeAppleAnchoredAdapter() -> AttestationHarness {
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

    // MARK: - App Attest call ordering

    /// Cases that pin what happens when two callers reach App Attest at once.
    ///
    /// `classify(_:keyId:operation:)` maps `DCError.invalidKey` onto three
    /// conditions by reading whether this adapter recorded an attestation for a
    /// key, and it discards that key for one of those three. That record
    /// describes App Attest's state only while no other App Attest call is
    /// outstanding, so `AppleDeviceAttestation` runs those calls one at a time.
    /// Each case below states one consequence of that ordering.
    struct AppAttestCallOrderingTests {
        private static let keyIdStorageKey = "dev.limn.scp.appAttest.keyId"
        private static let attestedKeyIdStorageKey = "dev.limn.scp.appAttest.attestedKeyId"

        @Test("a second attest racing a first keeps the key that first attest got attested")
        func concurrentAttestKeepsAttestedKey() async {
            // Apple answers a first `attestKey` with an attestation after a
            // round trip, and answers a second one — for a key it already
            // attested — with `DCError.invalidKey`. A second caller that reads
            // this adapter's attestation record before a first caller writes it
            // takes the rejected-key row and deletes a live Secure Enclave key.
            let defaults = InMemoryUserDefaults()
            let service = OverlapDetectingAppAttestService(
                attestScript: [
                    .init(result: .success(Data([0xA1, 0xA2])), delay: 0.20),
                    .init(result: .failure(OverlapDetectingAppAttestService.invalidKeyError), delay: 0)
                ],
                assertScript: [
                    .init(result: .success(Data([0xB1])), delay: 0)
                ]
            )
            let adapter = AppleDeviceAttestation(
                appId: CBORFixture.appId,
                service: service,
                defaults: defaults
            )

            async let first = adapter.attest(challenge: Data([0x01]), deviceId: Data([0x02]))
            // Let a first caller reach `attestKey` before a second caller
            // starts, so a second caller takes a second scripted answer.
            try? await Task.sleep(nanoseconds: 50_000_000)
            async let second = adapter.attest(challenge: Data([0x03]), deviceId: Data([0x04]))

            let firstOutcome = try? await first
            var secondError: AttestationError?
            do {
                let token = try await second
                Issue.record("a second attest returned \(token.count) bytes instead of throwing")
            } catch let error as AttestationError {
                secondError = error
            } catch {
                Issue.record("a second attest threw \(error), which is no AttestationError")
            }

            #expect(firstOutcome == Data([0xA1, 0xA2]))
            #expect(
                defaults.string(forKey: Self.keyIdStorageKey)
                    == OverlapDetectingAppAttestService.generatedKeyId,
                "a racing attest discarded a key Apple had attested"
            )
            #expect(
                defaults.string(forKey: Self.attestedKeyIdStorageKey)
                    == OverlapDetectingAppAttestService.generatedKeyId
            )
            guard case .keyAlreadyAttested = secondError else {
                Issue.record(
                    """
                    a second attest threw \(String(describing: secondError)) \
                    instead of AttestationError.keyAlreadyAttested
                    """
                )
                return
            }
        }

        @Test("App Attest sees one outstanding call at a time")
        func appAttestCallsNeverOverlap() async {
            // `peakConcurrency` counts calls this double had outstanding at
            // once. Six callers starting together drive it above one for an
            // adapter that hands every caller straight to App Attest.
            let defaults = InMemoryUserDefaults()
            let service = OverlapDetectingAppAttestService(
                attestScript: [.init(result: .success(Data([0xA1])), delay: 0.05)],
                assertScript: [.init(result: .success(Data([0xB1])), delay: 0.05)]
            )
            let adapter = AppleDeviceAttestation(
                appId: CBORFixture.appId,
                service: service,
                defaults: defaults
            )

            // One attestation first, so every assertion below finds a stored
            // key ID rather than throwing `keyNotFound` before it calls out.
            _ = try? await adapter.attest(challenge: Data([0x00]), deviceId: Data([0x01]))

            await withTaskGroup(of: Void.self) { group in
                for caller in 0 ..< 3 {
                    group.addTask {
                        _ = try? await adapter.attest(
                            challenge: Data([UInt8(caller)]),
                            deviceId: Data([0x02])
                        )
                    }
                    group.addTask {
                        _ = try? await adapter.assertRequest(
                            requestHash: Data(repeating: UInt8(caller), count: 32)
                        )
                    }
                }
            }

            #expect(
                service.peakConcurrency == 1,
                "App Attest saw \(service.peakConcurrency) outstanding calls at once"
            )
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
                defaults: InMemoryUserDefaults(),
                anchorCertificates: CBORFixture.testAnchors()
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

        @Test("verify rejects an x5c that repeats one certificate twice")
        func verifyRejectsDuplicatedCertificate() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            // Clause 3 assigns a credential certificate to position 0 and an
            // intermediate certificate to position 1, so a path whose leaf and
            // whose next certificate are one certificate fills neither
            // position. An intermediate carries `CA:TRUE`, so a path
            // evaluation rejects it as a leaf as well.
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

        @Test("verify rejects a credential certificate carrying a malformed issuer name")
        func verifyRejectsMalformedIssuerName() {
            let harness = makeAdapter()
            let adapter = harness.adapter

            // `retaggedIssuerCertificate` still parses, and its issuer name
            // matches no certificate's subject name, so a path evaluation
            // builds no path from it to an anchor.
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

        @Test("verify rejects an x5c whose element 1 issued no element 0")
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

            // `SecTrustCreateWithCertificates` reads its first argument as one
            // leaf plus a bag of helper certificates, so a reversed pair still
            // builds a path — one running from the intermediate to the anchor.
            // Comparing that path's first two certificates against elements 0
            // and 1 is what rejects this pair.
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

    // MARK: - verify(token:) trust-anchor tests, clause 3

    /// Cases that pin which certification authority clause 3 requires, and that
    /// pin how `verify(token:)` reaches that decision.
    ///
    /// Clause 3 of acceptance criterion 3 in ADR-025 states that element 1 of
    /// `x5c` is an Apple App Attest intermediate certificate. `readCertificateChain`
    /// decides that by evaluating `x5c` as a certification path anchored at
    /// Apple's App Attest root certificate, which is a certificate this binary
    /// carries. Two properties follow, and both get a case here: a chain nobody
    /// at Apple signed fails however well-formed the rest of the token is, and
    /// a chain carrying an intermediate Apple issued later still passes.
    struct AppAttestAppleAnchorTests {
        @Test("verify rejects a token whose x5c is a self-signed chain")
        func verifyRejectsSelfSignedChain() {
            // A self-signed chain is what an attacker mints with two `openssl`
            // commands: one root that signs itself, and one credential
            // certificate that root issues. Every other clause of criterion 3
            // holds for this token, so clause 3's anchor is what rejects it.
            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.attestationStatement(
                    certificates: [
                        CBORFixture.rogueCredentialCertificate,
                        CBORFixture.rogueRootCertificate
                    ]
                )
            )

            #expect(makeAppleAnchoredAdapter().adapter.verify(token: token) == false)
            #expect(makeUnsupportedAdapter().adapter.verify(token: token) == false)
        }

        @Test("verify rejects a chain reaching a root Apple did not sign")
        func verifyRejectsChainOutsideAppleAuthority() {
            // This chain is the one every accepting case in this file uses, and
            // `testRootCertificate` anchors it. An adapter carrying Apple's
            // root instead rejects it, which is what makes those accepting
            // cases evidence about structure rather than evidence about
            // authority.
            let harness = makeAppleAnchoredAdapter()

            #expect(harness.adapter.verify(token: CBORFixture.attestationObject()) == false)
        }

        @Test("verify accepts a chain carrying a replacement intermediate its root signed")
        func verifyAcceptsRotatedIntermediate() {
            // Apple replaces its App Attest intermediate certificate on its own
            // schedule. Anchoring at a root accepts whichever intermediate that
            // root signed, and this case fails for an implementation that
            // compares element 1 against a stored intermediate by name, by
            // public key, or by fingerprint.
            let harness = makeUnsupportedAdapter()

            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.attestationStatement(
                    certificates: [
                        CBORFixture.rotatedCredentialCertificate,
                        CBORFixture.rotatedIntermediateCertificate
                    ]
                )
            )
            #expect(harness.adapter.verify(token: token) == true)
        }

        @Test("verify rejects a credential certificate its stated intermediate did not issue")
        func verifyRejectsCrossedIntermediate() {
            // Both certificates here reach `testRootCertificate`, and neither
            // issued the other, so a check that only walked each certificate to
            // an anchor would accept this pair. Clause 3 assigns positions, and
            // an evaluated path that starts with element 0 and element 1 is
            // what rejects it.
            let harness = makeUnsupportedAdapter()

            let token = CBORFixture.attestationObject(
                attestationStatementValue: CBORFixture.attestationStatement(
                    certificates: [
                        CBORFixture.credentialCertificate,
                        CBORFixture.rotatedIntermediateCertificate
                    ]
                )
            )
            #expect(harness.adapter.verify(token: token) == false)
        }

        @Test("an adapter carrying no anchor accepts no chain")
        func emptyAnchorSetAcceptsNothing() {
            // `AppAttestAnchor.appleAppAttestRoot()` returns an empty array if
            // its bytes ever stop parsing, and this case pins what
            // `verify(token:)` does with such an array: it rejects a chain that
            // an anchor would otherwise accept, rather than skipping the
            // evaluation.
            let harness = makeUnsupportedAdapter(anchorCertificates: [])

            #expect(harness.adapter.verify(token: CBORFixture.attestationObject()) == false)
        }

        @Test("this binary carries Apple's App Attest root certificate")
        func appleAnchorParsesAndNamesApple() throws {
            let anchors = AppAttestAnchor.appleAppAttestRoot()
            #expect(anchors.count == 1)
            let certificate = try #require(anchors.first)

            // Apple publishes this certificate as
            // `Apple_App_Attestation_Root_CA.pem` at
            // https://www.apple.com/certificateauthority/private/, and SHA-256
            // of its DER encoding is the digest below.
            let der = SecCertificateCopyData(certificate) as Data
            let digest = Data(SHA256.hash(data: der))
                .map { String(format: "%02x", $0) }
                .joined()
            #expect(digest == "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932")

            let summary = SecCertificateCopySubjectSummary(certificate) as String?
            #expect(summary == "Apple App Attestation Root CA")
        }
    }

#endif // os(iOS) || os(macOS)
