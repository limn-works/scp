// Tests for adapter `AppleDeviceAttestation`.
//
// These tests pin three properties of `AppleDeviceAttestation`:
//
// 1. When `DCAppAttestService.isSupported` is `false`, `attest` and
//    `assertRequest` throw `ScpError` code `SCP-ATTEST-9019`, the type the
//    UniFFI callback declares, store no key ID, and return no bytes, even
//    though every App Attest method of the test service would answer with a
//    value.
//    §9.3 of SCP's security model spec, "Sybil resistance and identity
//    uniqueness", states that the absence of a device attestation is expected
//    and is not penalizing, so a typed error is an honest result and a
//    locally minted token would assert a hardware guarantee no hardware
//    produced.
// 2. `AttestationError.scpError` gives each `AttestationError` case its own
//    `SCP-ATTEST-` code, which `crates/scp-ffi/common/src/error_codes.rs`
//    registers.
// 3. When App Attest is supported, each answer of `generateKey`,
//    `attestKey` and `generateAssertion` (a value, an error, or neither)
//    reaches the caller of the `throws(ScpError)` methods either as bytes or
//    as the code of its `AttestationError` case, and `assertRequest` with no
//    stored key ID throws `SCP-ATTEST-9020`.
//
// See ADR-025 (Apple Platform Adapter) in `.docs/adrs/phase-5.md` and the
// UniFFI `DeviceAttestationProvider` callback interface in
// `crates/scp-ffi/uniffi/src/lib.rs`, which the adapter conforms to.

#if os(iOS) || os(macOS)

    import CryptoKit
    import DeviceCheck
    import Foundation
    @testable import SCP
    import Testing

    // MARK: - Test values

    /// The key ID, attestation and assertion a scripted App Attest call
    /// answers with when its script says `.value`.
    private let scriptedKeyId = "scripted-app-attest-key"
    private let scriptedAttestation = Data([0xA1, 0xA2, 0xA3])
    private let scriptedAssertion = Data([0xB1, 0xB2, 0xB3])

    /// The `UserDefaults` key `AppleDeviceAttestation` stores its key ID under.
    private let keyIdDefaultsKey = "dev.limn.scp.appAttest.keyId"

    private let challenge = Data(repeating: 0x01, count: 32)
    private let deviceId = Data([0x04, 0x05, 0x06])
    private let requestHash = Data(repeating: 0xAB, count: 32)

    // MARK: - Test doubles

    /// How a scripted App Attest call answers its completion handler.
    private enum Answer<Value> {
        /// A value and no error.
        case value(Value)
        /// An error and no value.
        case failure
        /// Neither a value nor an error, an answer Apple does not document.
        case neither

        func deliver(to handler: (Value?, Error?) -> Void) {
            switch self {
            case let .value(value): handler(value, nil)
            case .failure: handler(nil, NSError(domain: "AppleDeviceAttestationTests", code: 1))
            case .neither: handler(nil, nil)
            }
        }
    }

    /// A `DCAppAttestService` that reports `supported` from `isSupported` and
    /// answers `generateKey`, `attestKey` and `generateAssertion` as its
    /// script says, so a test drives each adapter path without the App Attest
    /// entitlement. Every answer defaults to a value, so an adapter that
    /// ignored `isSupported == false` would store a key ID and return bytes.
    private final class ScriptedAppAttestService: DCAppAttestService {
        private let reportsSupport: Bool
        private let key: Answer<String>
        private let attestation: Answer<Data>
        private let assertion: Answer<Data>

        init(
            supported: Bool,
            key: Answer<String> = .value(scriptedKeyId),
            attestation: Answer<Data> = .value(scriptedAttestation),
            assertion: Answer<Data> = .value(scriptedAssertion)
        ) {
            reportsSupport = supported
            self.key = key
            self.attestation = attestation
            self.assertion = assertion
            super.init()
        }

        override var isSupported: Bool {
            reportsSupport
        }

        override func generateKey(completionHandler: @escaping (String?, Error?) -> Void) {
            key.deliver(to: completionHandler)
        }

        override func attestKey(
            _: String,
            clientDataHash _: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            attestation.deliver(to: completionHandler)
        }

        override func generateAssertion(
            _: String,
            clientDataHash _: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            assertion.deliver(to: completionHandler)
        }
    }

    /// A `UserDefaults` that keeps every value in memory.
    ///
    /// `AppleDeviceAttestation` reads its key ID through `string(forKey:)` and
    /// writes it through `set(_:forKey:)`, so overriding those two methods
    /// covers every call it makes. A real `UserDefaults(suiteName:)` would
    /// leave one `~/Library/Preferences/<suiteName>.plist` behind per test,
    /// because `removePersistentDomain(forName:)` clears values and leaves that
    /// file, and because `cfprefsd` may write it after a test deleted it.
    /// Keeping values in memory writes nothing to delete.
    private final class InMemoryUserDefaults: UserDefaults {
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

    // MARK: - Helpers

    /// An adapter under test, together with a defaults store it writes to.
    private struct AttestationHarness {
        let adapter: AppleDeviceAttestation
        let defaults: UserDefaults
    }

    /// One scripted App Attest failure: the service that answers it, the
    /// `SCP-ATTEST-` code the adapter must throw, and the key ID stored
    /// before an `assertRequest` or expected after an `attest`.
    private struct FailureScript {
        let label: String
        let service: ScriptedAppAttestService
        let code: String
        let storedKeyId: String?

        init(_ label: String, _ service: ScriptedAppAttestService, _ code: String, storedKeyId: String?) {
            self.label = label
            self.service = service
            self.code = code
            self.storedKeyId = storedKeyId
        }
    }

    /// Build an adapter over `service`, with `storedKeyId` stored as its key ID
    /// when it is not `nil`.
    private func makeAdapter(
        _ service: ScriptedAppAttestService,
        storedKeyId: String? = nil
    ) -> AttestationHarness {
        let defaults = InMemoryUserDefaults()
        if let storedKeyId {
            defaults.set(storedKeyId, forKey: keyIdDefaultsKey)
        }
        let adapter = AppleDeviceAttestation(service: service, defaults: defaults)
        return AttestationHarness(adapter: adapter, defaults: defaults)
    }

    /// Require `call` to throw `ScpError.Identity` carrying `expectedCode`, the
    /// value the UniFFI `DeviceAttestationProvider` callback lowers into an
    /// error Rust receives, and return the message it carried.
    @discardableResult
    private func expectCode(
        _ expectedCode: String,
        from method: String,
        _ call: () async throws(ScpError) -> Data
    ) async -> String? {
        do throws(ScpError) {
            let bytes = try await call()
            Issue.record("\(method) returned \(bytes.count) bytes instead of throwing \(expectedCode)")
            return nil
        } catch {
            guard case let .Identity(msg, code) = error else {
                Issue.record("\(method) threw \(error) instead of ScpError.Identity")
                return nil
            }
            #expect(code == expectedCode, "\(method)")
            return msg
        }
    }

    // MARK: - Fail-closed tests

    struct AppleDeviceAttestationFailClosedTests {
        @Test("attest throws SCP-ATTEST-9019 and stores no key ID when App Attest is unavailable")
        func attestThrowsUnsupported() async {
            let harness = makeAdapter(ScriptedAppAttestService(supported: false))
            let msg = await expectCode("SCP-ATTEST-9019", from: "attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }
            #expect(msg?.contains("isSupported") == true)
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == nil)
        }

        @Test("assertRequest throws SCP-ATTEST-9019 with a key ID stored when App Attest is unavailable")
        func assertRequestThrowsUnsupported() async {
            let harness = makeAdapter(ScriptedAppAttestService(supported: false), storedKeyId: scriptedKeyId)
            let msg = await expectCode("SCP-ATTEST-9019", from: "assertRequest") { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }
            #expect(msg?.contains("isSupported") == true)
        }

        @Test("every AttestationError case maps to its own SCP-ATTEST code")
        func everyCaseHasItsOwnCode() {
            let cases: [AttestationError] = [
                .serviceError("m"), .unsupported("m"), .keyNotFound, .internalError("m")
            ]
            let codes = cases.compactMap { error -> String? in
                guard case let .Identity(_, code) = error.scpError else { return nil }
                return code
            }
            let expected = ["9001", "9019", "9020", "9025"]
            #expect(codes == expected.map { "SCP-ATTEST-\($0)" })
        }

        @Test("isHardwareBacked reports false when App Attest is unavailable")
        func isHardwareBackedReportsFalse() {
            let adapter = makeAdapter(ScriptedAppAttestService(supported: false)).adapter
            #expect(adapter.isHardwareBacked == false)
        }
    }

    // MARK: - Supported-service tests

    struct AppleDeviceAttestationSupportedTests {
        @Test("attest returns the attestation App Attest answers with and stores the generated key ID")
        func attestReturnsAttestation() async throws {
            let harness = makeAdapter(ScriptedAppAttestService(supported: true))
            let token = try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            #expect(token == scriptedAttestation)
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
        }

        @Test("attest maps each generateKey and attestKey failure to its SCP-ATTEST code")
        func attestMapsEachFailure() async {
            let scripts = [
                FailureScript("generateKey error", ScriptedAppAttestService(supported: true, key: .failure), "SCP-ATTEST-9001", storedKeyId: nil),
                FailureScript("generateKey neither", ScriptedAppAttestService(supported: true, key: .neither), "SCP-ATTEST-9025", storedKeyId: nil),
                FailureScript("attestKey error", ScriptedAppAttestService(supported: true, attestation: .failure), "SCP-ATTEST-9001", storedKeyId: scriptedKeyId),
                FailureScript("attestKey neither", ScriptedAppAttestService(supported: true, attestation: .neither), "SCP-ATTEST-9025", storedKeyId: scriptedKeyId)
            ]
            for script in scripts {
                let harness = makeAdapter(script.service)
                await expectCode(script.code, from: "attest (\(script.label))") { () async throws(ScpError) -> Data in
                    try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
                }
                #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == script.storedKeyId, "\(script.label)")
            }
        }

        @Test("assertRequest throws SCP-ATTEST-9020 when no key ID is stored")
        func assertRequestWithoutKeyThrowsKeyNotFound() async {
            let harness = makeAdapter(ScriptedAppAttestService(supported: true))
            await expectCode("SCP-ATTEST-9020", from: "assertRequest") { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }
        }

        @Test("assertRequest returns the assertion App Attest answers with for the stored key ID")
        func assertRequestReturnsAssertion() async throws {
            let harness = makeAdapter(ScriptedAppAttestService(supported: true), storedKeyId: scriptedKeyId)
            let assertion = try await harness.adapter.assertRequest(requestHash: requestHash)
            #expect(assertion == scriptedAssertion)
        }

        @Test("assertRequest maps each generateAssertion failure to its SCP-ATTEST code")
        func assertRequestMapsEachFailure() async {
            let scripts = [
                FailureScript("generateAssertion error", ScriptedAppAttestService(supported: true, assertion: .failure), "SCP-ATTEST-9001", storedKeyId: scriptedKeyId),
                FailureScript("generateAssertion neither", ScriptedAppAttestService(supported: true, assertion: .neither), "SCP-ATTEST-9025", storedKeyId: scriptedKeyId)
            ]
            for script in scripts {
                let harness = makeAdapter(script.service, storedKeyId: script.storedKeyId)
                await expectCode(script.code, from: "assertRequest (\(script.label))") { () async throws(ScpError) -> Data in
                    try await harness.adapter.assertRequest(requestHash: requestHash)
                }
            }
        }
    }

#endif // os(iOS) || os(macOS)
