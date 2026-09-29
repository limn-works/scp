// Tests for adapter `AppleDeviceAttestation`.
//
// These tests pin five properties of `AppleDeviceAttestation`:
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
//    as the code of its `AttestationError` case, `DCError.featureUnsupported`
//    from any of the three calls reaches it as `SCP-ATTEST-9019`, and
//    `assertRequest` with no stored key ID throws `SCP-ATTEST-9020`.
//    `assertRequest` passes the stored key ID and `requestHash` to
//    `generateAssertion` unchanged, and `attest` attests the key ID
//    `generateKey` produced.
// 4. `attest` hands Apple its 32-byte `challenge` as `clientDataHash`
//    unchanged, whatever `deviceId` is, and `assertRequest` hands Apple its
//    32-byte `requestHash` unchanged. Each method rejects an input of any
//    other length with `SCP-ATTEST-9026` before it calls App Attest, and
//    `attest` then generates no key. ADR-025 acceptance criterion 3 has the
//    Rust core pass the binding digest `D` and the assertion digest `A` of
//    §9.3.1 of the security model spec as those two inputs.
// 5. App Attest sees one outstanding call at a time: a call queued behind an
//    outstanding call reaches Apple only after that call answers, concurrent
//    `attest` calls on a device with no stored key generate one key, and
//    every adapter over one `UserDefaults` object shares one lock and one
//    call serializer. A call that the `isSupported` check or the 32-byte
//    check rejects returns while another call holds the serializer, so it
//    never waits in the queue. `AppAttestCallOrderingTests` pins each case.
//
// See ADR-025 (Apple Platform Adapter) in `.docs/adrs/phase-5.md` and the
// UniFFI `DeviceAttestationProvider` callback interface in
// `crates/scp-ffi/uniffi/src/lib.rs`, which the adapter conforms to.

#if os(iOS) || os(macOS)

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
        /// An error and no value, from a domain other than `DCErrorDomain`.
        case failure
        /// `DCError.featureUnsupported` and no value: App Attest refuses the
        /// call although `isSupported` reported `true`.
        case featureUnsupported
        /// Neither a value nor an error, an answer Apple does not document.
        case neither

        func deliver(to handler: (Value?, Error?) -> Void) {
            switch self {
            case let .value(value): handler(value, nil)
            case .failure: handler(nil, NSError(domain: "AppleDeviceAttestationTests", code: 1))
            case .featureUnsupported: handler(nil, DCError(.featureUnsupported))
            case .neither: handler(nil, nil)
            }
        }
    }

    /// A `DCAppAttestService` that reports `supported` from `isSupported` and
    /// answers `generateKey`, `attestKey` and `generateAssertion` as its
    /// script says, so a test drives each adapter path without the App Attest
    /// entitlement. Every answer defaults to a value, so an adapter that
    /// ignored `isSupported == false` would store a key ID and return bytes.
    /// It records the key ID and `clientDataHash` the adapter passes to
    /// `attestKey` and `generateAssertion`, so a test can check the arguments
    /// App Attest receives.
    private final class ScriptedAppAttestService: DCAppAttestService {
        private let reportsSupport: Bool
        private let lock = NSLock()
        private var attestKeyArguments: (keyId: String, clientDataHash: Data)?
        private var generateAssertionArguments: (keyId: String, clientDataHash: Data)?

        /// The key ID of the last `attestKey` call, or `nil` if none was made.
        var attestKeyKeyId: String? {
            lock.withLock { attestKeyArguments?.keyId }
        }

        /// The key ID and `clientDataHash` of the last `generateAssertion`
        /// call, or `nil` if none was made.
        var generateAssertionCall: (keyId: String, clientDataHash: Data)? {
            lock.withLock { generateAssertionArguments }
        }

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
            _ keyId: String,
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            lock.withLock { attestKeyArguments = (keyId, clientDataHash) }
            attestation.deliver(to: completionHandler)
        }

        override func generateAssertion(
            _ keyId: String,
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            lock.withLock { generateAssertionArguments = (keyId, clientDataHash) }
            assertion.deliver(to: completionHandler)
        }
    }

    /// A `DCAppAttestService` that reports App Attest as available, counts how
    /// many times a caller asked it to generate a key, and answers every
    /// `attestKey` with an error, so a case reads the key count and nothing
    /// else.
    private final class CountingAppAttestService: DCAppAttestService {
        /// A key ID this double hands back to every caller.
        static let keyId = Data(repeating: 0x01, count: 32).base64EncodedString()

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
            completionHandler(nil, NSError(domain: DCErrorDomain, code: DCError.serverUnavailable.rawValue))
        }
    }

    /// A `DCAppAttestService` that answers `attestKey` and `generateAssertion`
    /// from a script after a scripted delay, and records the most calls it had
    /// outstanding at one moment.
    ///
    /// Each script is consumed front to back, and its last entry answers every
    /// call after it.
    private final class OverlapDetectingAppAttestService: DCAppAttestService {
        /// The key ID the `ordinal`th `generateKey` hands back, counting from 0.
        static func generatedKeyId(_ ordinal: Int) -> String {
            Data(repeating: 0x40 + UInt8(ordinal), count: 32).base64EncodedString()
        }

        /// The error an empty script answers with.
        static let emptyScriptError = NSError(domain: "AppleDeviceAttestationTests", code: 3)

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
        private var keyGenerationCallCount = 0

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
            let ordinal = lock.withLock {
                defer { keyGenerationCallCount += 1 }
                return keyGenerationCallCount
            }
            completionHandler(Self.generatedKeyId(ordinal), nil)
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
                    return Answer(result: .failure(Self.emptyScriptError), delay: 0)
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

    /// A `DCAppAttestService` that reports `isSupported == true`, answers every
    /// call with a value or with `assertionResult`, and records the key ID and
    /// `clientDataHash` of every `attestKey` and `generateAssertion` call in
    /// arrival order, so a test checks the exact bytes the adapter hands
    /// Apple. With `holdsFirstAssertion`, it answers its first
    /// `generateAssertion` only when a case calls `releaseHeldAssertion()`, so
    /// a case keeps one App Attest call outstanding for as long as it needs.
    private final class RecordingAppAttestService: DCAppAttestService {
        /// The key ID the `ordinal`th `generateKey` call hands back, counting
        /// from 1. Apple returns a new key ID for every generated key, so each
        /// call answers a different ID.
        static func generatedKeyId(_ ordinal: Int) -> String {
            Data(repeating: UInt8(0x50 + ordinal), count: 32).base64EncodedString()
        }

        /// One App Attest call this double received.
        struct Call: Equatable {
            let keyId: String
            let clientDataHash: Data
        }

        private let lock = NSLock()
        private var attestCalls: [Call] = []
        private var assertCalls: [Call] = []
        private var keysGenerated = 0
        private var heldAssertion: ((Data?, Error?) -> Void)?
        private let holdsFirstAssertion: Bool
        private let assertionResult: Result<Data, Error>

        init(holdsFirstAssertion: Bool = false, assertionResult: Result<Data, Error> = .success(scriptedAssertion)) {
            self.holdsFirstAssertion = holdsFirstAssertion
            self.assertionResult = assertionResult
            super.init()
        }

        /// Every `attestKey` call, in arrival order.
        var attestations: [Call] {
            lock.withLock { attestCalls }
        }

        /// Every `generateAssertion` call, in arrival order.
        var assertions: [Call] {
            lock.withLock { assertCalls }
        }

        /// The number of `generateKey` calls this double answered.
        var generatedKeyCount: Int {
            lock.withLock { keysGenerated }
        }

        /// Whether the first assertion is waiting for `releaseHeldAssertion()`.
        var isHoldingAssertion: Bool {
            lock.withLock { heldAssertion != nil }
        }

        override var isSupported: Bool {
            true
        }

        override func generateKey(completionHandler: @escaping (String?, Error?) -> Void) {
            let ordinal: Int = lock.withLock {
                keysGenerated += 1
                return keysGenerated
            }
            completionHandler(Self.generatedKeyId(ordinal), nil)
        }

        override func attestKey(
            _ keyId: String,
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            lock.withLock { attestCalls.append(Call(keyId: keyId, clientDataHash: clientDataHash)) }
            completionHandler(scriptedAttestation, nil)
        }

        override func generateAssertion(
            _ keyId: String,
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            let hold: Bool = lock.withLock {
                assertCalls.append(Call(keyId: keyId, clientDataHash: clientDataHash))
                if holdsFirstAssertion, assertCalls.count == 1 {
                    heldAssertion = completionHandler
                    return true
                }
                return false
            }
            if hold {
                return
            }
            deliver(assertionResult, to: completionHandler)
        }

        /// Answer the held first assertion with this double's assertion result.
        func releaseHeldAssertion() {
            let handler: ((Data?, Error?) -> Void)? = lock.withLock {
                defer { heldAssertion = nil }
                return heldAssertion
            }
            if let handler {
                deliver(assertionResult, to: handler)
            }
        }

        private func deliver(_ result: Result<Data, Error>, to completionHandler: (Data?, Error?) -> Void) {
            switch result {
            case let .success(data):
                completionHandler(data, nil)
            case let .failure(error):
                completionHandler(nil, error)
            }
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
    /// error a Rust caller receives, and return the message it carried.
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

    /// Run `call` and return the `SCP-ATTEST-` code of the `ScpError.Identity`
    /// it threw, `"returned bytes"` when it returned, or a description of any
    /// other error.
    private func code(of call: @Sendable () async throws(ScpError) -> Data) async -> String {
        do throws(ScpError) {
            _ = try await call()
            return "returned bytes"
        } catch {
            guard case let .Identity(_, code) = error else { return "\(error)" }
            return code
        }
    }

    /// Poll `condition` every millisecond until it holds or `milliseconds`
    /// pass, and report whether it held. The bound makes a case whose
    /// condition never holds fail instead of hanging the suite.
    private func waitUntil(milliseconds: Int = 10000, _ condition: () -> Bool) async -> Bool {
        for _ in 0 ..< milliseconds {
            if condition() {
                return true
            }
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
        return condition()
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

        /// The supported-device side of this order is pinned by the SCP-ATTEST-9026
        /// tests over `RecordingAppAttestService`, whose `isSupported` is true.
        @Test("attest throws SCP-ATTEST-9019, not SCP-ATTEST-9026, for a wrong-length challenge when App Attest is unavailable")
        func attestUnsupportedPrecedesLengthCheck() async {
            for length in [0, 31, 33] {
                let harness = makeAdapter(ScriptedAppAttestService(supported: false))
                let msg = await expectCode("SCP-ATTEST-9019", from: "attest (\(length) bytes)") { () async throws(ScpError) -> Data in
                    try await harness.adapter.attest(challenge: Data(repeating: 0x01, count: length), deviceId: deviceId)
                }
                #expect(msg?.contains("isSupported") == true)
                #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == nil)
            }
        }

        @Test("assertRequest throws SCP-ATTEST-9019, not SCP-ATTEST-9026, for a wrong-length requestHash when App Attest is unavailable")
        func assertRequestUnsupportedPrecedesLengthCheck() async {
            for length in [0, 31, 33] {
                let harness = makeAdapter(ScriptedAppAttestService(supported: false), storedKeyId: scriptedKeyId)
                let msg = await expectCode("SCP-ATTEST-9019", from: "assertRequest (\(length) bytes)") { () async throws(ScpError) -> Data in
                    try await harness.adapter.assertRequest(requestHash: Data(repeating: 0xAB, count: length))
                }
                #expect(msg?.contains("isSupported") == true)
            }
        }

        @Test("every AttestationError case maps to its own SCP-ATTEST code")
        func everyCaseHasItsOwnCode() {
            let cases: [AttestationError] = [
                .serviceError("m"), .unsupported("m"), .keyNotFound, .internalError("m"), .invalidClientDataHash("m")
            ]
            let codes = cases.compactMap { error -> String? in
                guard case let .Identity(_, code) = error.scpError else { return nil }
                return code
            }
            let expected = ["9001", "9019", "9020", "9025", "9026"]
            #expect(codes == expected.map { "SCP-ATTEST-\($0)" })
        }

        @Test("isAppAttestSupported reports false when isSupported is false")
        func isAppAttestSupportedReportsFalse() {
            let adapter = makeAdapter(ScriptedAppAttestService(supported: false)).adapter
            #expect(adapter.isAppAttestSupported == false)
        }

        @Test("isAppAttestSupported reads true while attest throws SCP-ATTEST-9019 on featureUnsupported")
        func isAppAttestSupportedDoesNotPredictFeatureUnsupported() async {
            let harness = makeAdapter(ScriptedAppAttestService(supported: true, key: .featureUnsupported))
            #expect(harness.adapter.isAppAttestSupported == true)
            await expectCode("SCP-ATTEST-9019", from: "attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }
        }
    }

    // MARK: - Supported-service tests

    struct AppleDeviceAttestationSupportedTests {
        @Test("attest returns the attestation App Attest answers with, attests the generated key ID and stores it")
        func attestReturnsAttestation() async throws {
            let service = ScriptedAppAttestService(supported: true)
            let harness = makeAdapter(service)
            let token = try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            #expect(token == scriptedAttestation)
            #expect(service.attestKeyKeyId == scriptedKeyId)
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
        }

        @Test("attest maps each generateKey and attestKey failure to its SCP-ATTEST code")
        func attestMapsEachFailure() async {
            let scripts = [
                FailureScript("generateKey error", ScriptedAppAttestService(supported: true, key: .failure), "SCP-ATTEST-9001", storedKeyId: nil),
                FailureScript("generateKey featureUnsupported", ScriptedAppAttestService(supported: true, key: .featureUnsupported), "SCP-ATTEST-9019", storedKeyId: nil),
                FailureScript("generateKey neither", ScriptedAppAttestService(supported: true, key: .neither), "SCP-ATTEST-9025", storedKeyId: nil),
                FailureScript("attestKey error", ScriptedAppAttestService(supported: true, attestation: .failure), "SCP-ATTEST-9001", storedKeyId: scriptedKeyId),
                FailureScript("attestKey featureUnsupported", ScriptedAppAttestService(supported: true, attestation: .featureUnsupported), "SCP-ATTEST-9019", storedKeyId: scriptedKeyId),
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

        @Test("assertRequest passes the stored key ID and requestHash unchanged to generateAssertion and returns its assertion")
        func assertRequestReturnsAssertion() async throws {
            let service = ScriptedAppAttestService(supported: true)
            // A stored key ID other than the one `generateKey` would answer
            // with, so a test that passed shows the adapter asserted with the
            // stored key and generated none.
            let storedKeyId = "stored-app-attest-key"
            let harness = makeAdapter(service, storedKeyId: storedKeyId)
            let assertion = try await harness.adapter.assertRequest(requestHash: requestHash)
            #expect(assertion == scriptedAssertion)
            let call = try #require(service.generateAssertionCall)
            #expect(call.keyId == storedKeyId)
            #expect(call.clientDataHash == requestHash)
        }

        @Test("assertRequest maps each generateAssertion failure to its SCP-ATTEST code")
        func assertRequestMapsEachFailure() async {
            let scripts = [
                FailureScript("generateAssertion error", ScriptedAppAttestService(supported: true, assertion: .failure), "SCP-ATTEST-9001", storedKeyId: scriptedKeyId),
                FailureScript("generateAssertion featureUnsupported", ScriptedAppAttestService(supported: true, assertion: .featureUnsupported), "SCP-ATTEST-9019", storedKeyId: scriptedKeyId),
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

    // MARK: - Client data tests

    /// Cases that pin the bytes `AppleDeviceAttestation` hands Apple.
    struct AppAttestClientDataTests {
        @Test("attest hands Apple challenge unchanged, whatever deviceId is, and returns the raw attestation object")
        func attestForwardsChallenge() async throws {
            let service = RecordingAppAttestService()
            let adapter = AppleDeviceAttestation(service: service, defaults: InMemoryUserDefaults())
            let challenge = Data((0 ..< 32).map { UInt8($0) })

            let attestation = try await adapter.attest(challenge: challenge, deviceId: Data([0xFF, 0xEE]))

            #expect(attestation == scriptedAttestation)
            #expect(service.attestations == [
                .init(keyId: RecordingAppAttestService.generatedKeyId(1), clientDataHash: challenge)
            ])
        }

        @Test("attest rejects a challenge that is not 32 bytes before it generates a key or calls Apple")
        func attestRejectsWrongLengthChallenge() async {
            for length in [0, 31, 33] {
                let service = RecordingAppAttestService()
                let defaults = InMemoryUserDefaults()
                let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

                let msg = await expectCode("SCP-ATTEST-9026", from: "attest (\(length) bytes)") { () async throws(ScpError) -> Data in
                    try await adapter.attest(challenge: Data(repeating: 0x01, count: length), deviceId: deviceId)
                }
                #expect(msg?.contains("\(length) bytes") == true)
                #expect(service.generatedKeyCount == 0)
                #expect(defaults.string(forKey: keyIdDefaultsKey) == nil)
                #expect(service.attestations.isEmpty)
                #expect(service.assertions.isEmpty)
            }
        }

        @Test("assertRequest rejects a requestHash that is not 32 bytes before it calls Apple")
        func assertRequestRejectsWrongLengthRequestHash() async {
            for length in [0, 31, 33, 57] {
                let service = RecordingAppAttestService()
                let defaults = InMemoryUserDefaults()
                // A stored key ID, so an adapter without the length check would
                // reach `generateAssertion` rather than throw SCP-ATTEST-9020.
                defaults.set(RecordingAppAttestService.generatedKeyId(1), forKey: keyIdDefaultsKey)
                let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

                let msg = await expectCode("SCP-ATTEST-9026", from: "assertRequest (\(length) bytes)") { () async throws(ScpError) -> Data in
                    try await adapter.assertRequest(requestHash: Data(repeating: 0x01, count: length))
                }
                #expect(msg?.contains("\(length) bytes") == true)
                #expect(service.assertions.isEmpty)
            }
        }

        @Test("assertRequest hands Apple requestHash unchanged")
        func assertRequestForwardsRequestHash() async throws {
            let service = RecordingAppAttestService()
            let adapter = AppleDeviceAttestation(service: service, defaults: InMemoryUserDefaults())
            _ = try await adapter.attest(challenge: challenge, deviceId: deviceId)

            let requestHash = Data((0 ..< 32).map { UInt8(0xFF - $0) })
            let assertion = try await adapter.assertRequest(requestHash: requestHash)

            #expect(assertion == scriptedAssertion)
            #expect(service.assertions == [
                .init(keyId: RecordingAppAttestService.generatedKeyId(1), clientDataHash: requestHash)
            ])
        }
    }

    // MARK: - Call ordering tests

    /// A call a check must reject before it is queued, and the code it throws.
    private struct RejectedCall {
        let label: String
        let code: String
        let call: @Sendable () async throws(ScpError) -> Data

        init(_ label: String, _ code: String, _ call: @escaping @Sendable () async throws(ScpError) -> Data) {
            self.label = label
            self.code = code
            self.call = call
        }
    }

    /// Cases that pin `AppleDeviceAttestation`'s call serializer: App Attest
    /// sees one outstanding call at a time, in arrival order, across every
    /// adapter over one `UserDefaults` object, and the `isSupported` and
    /// 32-byte checks run before a call is queued.
    struct AppAttestCallOrderingTests {
        @Test("App Attest sees one outstanding call at a time")
        func appAttestCallsNeverOverlap() async {
            // `peakConcurrency` counts calls this double had outstanding at
            // once. Six callers starting together drive it above one for an
            // adapter that hands every caller straight to App Attest.
            let service = OverlapDetectingAppAttestService(
                attestScript: [.init(result: .success(Data([0xA1])), delay: 0.05)],
                assertScript: [.init(result: .success(Data([0xB1])), delay: 0.05)]
            )
            let adapter = AppleDeviceAttestation(service: service, defaults: InMemoryUserDefaults())

            // One attestation first, so every assertion below finds a stored
            // key ID rather than throwing `keyNotFound` before it calls out.
            _ = try? await adapter.attestReportingAttestationError(challenge: challenge, deviceId: deviceId)

            await withTaskGroup(of: Void.self) { group in
                for caller in 0 ..< 3 {
                    group.addTask {
                        _ = try? await adapter.attestReportingAttestationError(
                            challenge: Data(repeating: UInt8(caller), count: 32),
                            deviceId: deviceId
                        )
                    }
                    group.addTask {
                        _ = try? await adapter.assertRequestReportingAttestationError(
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

        @Test("a call queued behind an outstanding call reaches Apple only after that call answers, even with an error")
        func queuedCallWaitsForOutstandingCall() async {
            let service = RecordingAppAttestService(
                holdsFirstAssertion: true,
                assertionResult: .failure(NSError(domain: "AppleDeviceAttestationTests", code: 2))
            )
            let defaults = InMemoryUserDefaults()
            defaults.set(RecordingAppAttestService.generatedKeyId(1), forKey: keyIdDefaultsKey)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)
            let secondHash = Data(repeating: 0xCD, count: 32)

            let first = Task { await code(of: { () async throws(ScpError) -> Data in
                try await adapter.assertRequest(requestHash: requestHash)
            }) }
            #expect(await waitUntil { service.isHoldingAssertion }, "the first assertRequest never reached Apple")
            let second = Task { await code(of: { () async throws(ScpError) -> Data in
                try await adapter.assertRequest(requestHash: secondHash)
            }) }

            // An adapter that hands every caller straight to App Attest lets
            // the second call reach Apple within milliseconds; 200 ms bounds
            // that window. The serializer keeps it out until the first answers.
            let secondReachedApple = await waitUntil(milliseconds: 200) { service.assertions.count > 1 }
            #expect(!secondReachedApple, "a queued assertRequest reached Apple while an earlier call was outstanding")

            service.releaseHeldAssertion()
            #expect(await first.value == "SCP-ATTEST-9001")
            #expect(await second.value == "SCP-ATTEST-9001")
            #expect(service.assertions.map(\.clientDataHash) == [requestHash, secondHash])
        }

        @Test("a call the isSupported or 32-byte check rejects returns while another call holds the serializer")
        func rejectedCallsNeverEnterTheSerializer() async {
            let service = RecordingAppAttestService(holdsFirstAssertion: true)
            let defaults = InMemoryUserDefaults()
            defaults.set(RecordingAppAttestService.generatedKeyId(1), forKey: keyIdDefaultsKey)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)
            // An adapter over the same defaults shares `adapter`'s serializer,
            // and its service reports no App Attest, so it reaches the
            // `isSupported` check while `adapter` holds the serializer.
            let unsupported = AppleDeviceAttestation(service: ScriptedAppAttestService(supported: false), defaults: defaults)
            #expect(adapter.sharesKeyState(with: unsupported))

            let held = Task { await code(of: { () async throws(ScpError) -> Data in
                try await adapter.assertRequest(requestHash: requestHash)
            }) }
            #expect(await waitUntil { service.isHoldingAssertion }, "the held assertRequest never reached Apple")

            let short = Data(repeating: 0x01, count: 31)
            let rejected = [
                RejectedCall("attest, 31-byte challenge", "SCP-ATTEST-9026") { () async throws(ScpError) -> Data in
                    try await adapter.attest(challenge: short, deviceId: deviceId)
                },
                RejectedCall("assertRequest, 31-byte requestHash", "SCP-ATTEST-9026") { () async throws(ScpError) -> Data in
                    try await adapter.assertRequest(requestHash: short)
                },
                RejectedCall("attest, App Attest unsupported", "SCP-ATTEST-9019") { () async throws(ScpError) -> Data in
                    try await unsupported.attest(challenge: challenge, deviceId: deviceId)
                },
                RejectedCall("assertRequest, App Attest unsupported", "SCP-ATTEST-9019") { () async throws(ScpError) -> Data in
                    try await unsupported.assertRequest(requestHash: requestHash)
                }
            ]
            for entry in rejected {
                // The rejected call races a five-second timer. A call that
                // waited in the queue behind the held assertion loses, and the
                // held assertion is released so the waiting call can finish.
                let outcome: String = await withTaskGroup(of: String.self) { group in
                    group.addTask { await code(of: entry.call) }
                    group.addTask {
                        try? await Task.sleep(nanoseconds: 5_000_000_000)
                        return "timed out"
                    }
                    let first = await group.next() ?? "no result"
                    if first == "timed out" {
                        service.releaseHeldAssertion()
                    }
                    group.cancelAll()
                    return first
                }
                #expect(outcome == entry.code, "\(entry.label)")
            }

            #expect(service.isHoldingAssertion, "a rejected call waited for the held assertion")
            service.releaseHeldAssertion()
            #expect(await held.value == "returned bytes")
            #expect(service.generatedKeyCount == 0)
            #expect(service.attestations.isEmpty)
            #expect(service.assertions.count == 1)
        }

        @Test("concurrent attests on a device with no stored key generate one App Attest key, over 50 rounds")
        func concurrentAttestsGenerateOneKey() async {
            // Eight callers start `attest` together on one fresh adapter, so
            // the device must end up holding one Secure Enclave App Attest key.
            // This case fails when `attest` stops routing key generation
            // through `AppAttestCallSerializer`. 50 rounds guard against a
            // scheduler that happens to order one round's callers one after
            // another.
            for round in 0 ..< 50 {
                let defaults = InMemoryUserDefaults()
                let service = CountingAppAttestService()
                let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

                await withTaskGroup(of: Void.self) { group in
                    for caller in 0 ..< 8 {
                        group.addTask {
                            _ = try? await adapter.attestReportingAttestationError(
                                challenge: Data(repeating: UInt8(caller), count: 32),
                                deviceId: deviceId
                            )
                        }
                    }
                }

                #expect(
                    service.keyGenerationCount == 1,
                    "round \(round) generated \(service.keyGenerationCount) App Attest keys"
                )
                #expect(defaults.string(forKey: keyIdDefaultsKey) == CountingAppAttestService.keyId)
            }
        }

        @Test("adapters over one defaults object share one lock and one serializer, and adapters over two do not")
        func adaptersShareKeyStatePerDefaultsObject() {
            // Every adapter `init()` builds reads `UserDefaults.standard`,
            // which the process shares, so its App Attest calls have to run
            // in one order with every other such adapter's calls.
            #expect(AppleDeviceAttestation().sharesKeyState(with: AppleDeviceAttestation()))
            let defaults = InMemoryUserDefaults()
            let service = ScriptedAppAttestService(supported: true)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)
            #expect(adapter.sharesKeyState(with: AppleDeviceAttestation(service: service, defaults: defaults)))
            #expect(!adapter.sharesKeyState(with: AppleDeviceAttestation(service: service, defaults: InMemoryUserDefaults())))
        }
    }

#endif // os(iOS) || os(macOS)
