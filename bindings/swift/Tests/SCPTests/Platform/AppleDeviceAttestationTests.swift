// Fail-closed, key-lifecycle, and call-ordering tests for adapter
// `AppleDeviceAttestation`.
//
// These tests pin five properties of `AppleDeviceAttestation`:
//
// 1. When `DCAppAttestService.isSupported` is `false`, `attest` and
//    `assertRequest` throw `ScpError` code `SCP-ATTEST-9019`, the type the
//    UniFFI callback declares, and return no bytes.
//    §9.3 of SCP's security model spec, "Sybil resistance and identity
//    uniqueness", states that the absence of a device attestation is expected
//    and is not penalizing, so a typed error is an honest result and a
//    locally minted token would assert a hardware guarantee no hardware
//    produced.
// 2. Concurrent calls to `attest` over an unattested key generate one App
//    Attest key. `AppAttestCallSerializer` runs each `attest` body, key
//    generation included, after the previous body finished, so the first
//    caller stores its key ID before a second caller reads one.
// 3. Concurrent calls reach Apple's App Attest service one at a time, and a
//    second `attest` therefore reads the attestation a first `attest` recorded
//    and attests a replacement key rather than the key Apple already attested.
//    Each queued call also reads the stored key ID after its predecessors
//    finished, so it never names a key ID a predecessor discarded.
// 4. `attest` hands Apple the 32-byte `challenge` unchanged as
//    `clientDataHash`, rejects any other length before it generates a key, and
//    returns the raw attestation object; `assertRequest` hands Apple
//    `requestHash` unchanged, rejecting any other length before it calls
//    Apple. ADR-025 acceptance criterion 3 fixes both.
// 5. `DCError.invalidKey` maps onto the three conditions `DCError.h` lists,
//    each of which keeps or discards a key ID by its own rule, and a key
//    generated to replace an attested key leaves the attested key in place
//    until Apple attests the replacement. `AppAttestKeyLifecycleTests` pins
//    each condition, `AppAttestKeyReplacementTests` pins the replacement,
//    and `AppAttestIncompleteAnswerTests` pins the
//    `SCP-ATTEST-9025` result of an App Attest answer that carries neither a
//    value nor an error.
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

    /// A `DCAppAttestService` that reports App Attest as available, counts how
    /// many times a caller asked it to generate a key, and answers every
    /// `attestKey` with `DCError.serverUnavailable`, so its key stays
    /// unattested and every later `attest` reuses it.
    private final class CountingAppAttestService: DCAppAttestService, @unchecked Sendable {
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
        /// The key ID a first `generateKey` hands back.
        static let generatedKeyId = Data(repeating: 0x03, count: 32).base64EncodedString()

        /// The key ID every later `generateKey` hands back.
        static let secondGeneratedKeyId = Data(repeating: 0x07, count: 32).base64EncodedString()

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
        private var assertionKeyIds: [String] = []
        private var assertionClientDataHashes: [Data] = []

        /// The key ID of every `generateAssertion` call, in arrival order.
        var assertedKeyIds: [String] {
            lock.withLock { assertionKeyIds }
        }

        /// The `clientDataHash` of every `generateAssertion` call, in arrival
        /// order.
        var assertedClientDataHashes: [Data] {
            lock.withLock { assertionClientDataHashes }
        }

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
            let count = lock.withLock {
                keyGenerationCallCount += 1
                return keyGenerationCallCount
            }
            completionHandler(count == 1 ? Self.generatedKeyId : Self.secondGeneratedKeyId, nil)
        }

        override func attestKey(
            _: String,
            clientDataHash _: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            answer(from: \.attestScript, to: completionHandler)
        }

        override func generateAssertion(
            _ keyId: String,
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            lock.withLock {
                assertionKeyIds.append(keyId)
                assertionClientDataHashes.append(clientDataHash)
            }
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
        /// The key ID the `ordinal`th `generateKey` hands back, counting from 0.
        static func generatedKeyId(_ ordinal: Int) -> String {
            Data(repeating: 0x40 + UInt8(ordinal), count: 32).base64EncodedString()
        }

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
        private var keyGenerationCallCount = 0
        private var attestKeyIds: [String] = []

        /// Most calls this double had outstanding at one moment.
        var peakConcurrency: Int {
            lock.withLock { peakOutstandingCalls }
        }

        /// The key ID of every `attestKey` call, in arrival order.
        var attestedKeyIds: [String] {
            lock.withLock { attestKeyIds }
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
            _ keyId: String,
            clientDataHash _: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            lock.withLock { attestKeyIds.append(keyId) }
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

    /// A `DCAppAttestService` that records the key ID and the
    /// `clientDataHash` of every call, and can hold its first assertion until
    /// a case releases it.
    ///
    /// `ScriptedAppAttestService` records the `clientDataHash` of assertions
    /// only, and every other double ignores `clientDataHash`, so no other
    /// double notices a change to the bytes `attest` hands Apple.
    private final class RecordingAppAttestService: DCAppAttestService, @unchecked Sendable {
        /// A key ID `generateKey` hands back.
        static let generatedKeyId = Data(repeating: 0x05, count: 32).base64EncodedString()

        /// What Apple returns for each of three `DCError.invalidKey` conditions.
        static let invalidKeyError = NSError(
            domain: DCErrorDomain,
            code: DCError.invalidKey.rawValue,
            userInfo: nil
        )

        /// One App Attest call this double received.
        struct Call: Equatable {
            let keyId: String
            let clientDataHash: Data
        }

        private let lock = NSLock()
        private var attestCalls: [Call] = []
        private var assertCalls: [Call] = []
        private var heldAssertion: ((Data?, Error?) -> Void)?
        private let holdsFirstAssertion: Bool
        private let assertionResult: Result<Data, Error>

        /// Every `attestKey` call, in arrival order.
        var attestations: [Call] {
            lock.withLock { attestCalls }
        }

        /// Every `generateAssertion` call, in arrival order.
        var assertions: [Call] {
            lock.withLock { assertCalls }
        }

        /// Whether the first assertion is waiting for `releaseHeldAssertion()`.
        var isHoldingAssertion: Bool {
            lock.withLock { heldAssertion != nil }
        }

        init(holdsFirstAssertion: Bool = false, assertionResult: Result<Data, Error> = .success(Data([0xB1]))) {
            self.holdsFirstAssertion = holdsFirstAssertion
            self.assertionResult = assertionResult
            super.init()
        }

        override var isSupported: Bool {
            true
        }

        override func generateKey(completionHandler: @escaping (String?, Error?) -> Void) {
            completionHandler(Self.generatedKeyId, nil)
        }

        override func attestKey(
            _ keyId: String,
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            lock.withLock { attestCalls.append(Call(keyId: keyId, clientDataHash: clientDataHash)) }
            completionHandler(Data([0xA1]), nil)
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
    /// `AppleDeviceAttestation` reads, writes, and removes three string keys, so
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
            service: UnsupportedAppAttestService(),
            defaults: defaults
        )
        return AttestationHarness(adapter: adapter, defaults: defaults)
    }

    // MARK: - Fail-closed tests

    struct AppleDeviceAttestationFailClosedTests {
        /// Require `ScpError.Identity` carrying `SCP-ATTEST-9019`, the value the
        /// UniFFI `DeviceAttestationProvider` callback lowers into an error
        /// Rust receives.
        private func expectUnsupported(_ error: ScpError, from method: String) {
            guard case let .Identity(msg, code) = error else {
                Issue.record("\(method) threw \(error) instead of ScpError.Identity")
                return
            }
            #expect(code == "SCP-ATTEST-9019")
            #expect(msg.contains("isSupported"))
        }

        @Test("attest throws ScpError SCP-ATTEST-9019 when App Attest is unavailable")
        func attestThrowsUnsupported() async {
            let adapter = makeUnsupportedAdapter().adapter
            do throws(ScpError) {
                let token = try await adapter.attest(
                    challenge: Data(repeating: 0x01, count: 32),
                    deviceId: Data([0x04, 0x05, 0x06])
                )
                Issue.record("attest returned \(token.count) bytes on a device without App Attest")
            } catch {
                expectUnsupported(error, from: "attest")
            }
        }

        @Test("assertRequest throws ScpError SCP-ATTEST-9019 when App Attest is unavailable")
        func assertRequestThrowsUnsupported() async {
            let adapter = makeUnsupportedAdapter().adapter
            do throws(ScpError) {
                let assertion = try await adapter.assertRequest(requestHash: Data(repeating: 0xAB, count: 32))
                Issue.record("assertRequest returned \(assertion.count) bytes on a device without App Attest")
            } catch {
                expectUnsupported(error, from: "assertRequest")
            }
        }

        @Test("every AttestationError case maps to its own SCP-ATTEST code")
        func everyCaseHasItsOwnCode() {
            let cases: [AttestationError] = [
                .serviceError("m"), .unsupported("m"), .keyNotFound, .keyAlreadyAttested("m"),
                .keyNotAttested("m"), .keyRejected("m"), .serverUnavailable("m"), .internalError("m"),
                .invalidChallenge("m")
            ]
            let codes = cases.compactMap { error -> String? in
                guard case let .Identity(_, code) = error.scpError else { return nil }
                return code
            }
            let expected = ["9001", "9019", "9020", "9021", "9022", "9023", "9024", "9025", "9026"]
            #expect(codes == expected.map { "SCP-ATTEST-\($0)" })
        }

        @Test("an attest on a device without App Attest stores no App Attest key ID")
        func unsupportedAttestStoresNoKeyId() async {
            let harness = makeUnsupportedAdapter()
            let adapter = harness.adapter

            _ = try? await adapter.attestReportingAttestationError(challenge: Data(repeating: 0x01, count: 32), deviceId: Data([0x02]))

            #expect(harness.defaults.string(forKey: "dev.limn.scp.appAttest.keyId") == nil)
        }

        @Test("isHardwareBacked reports false when App Attest is unavailable")
        func isHardwareBackedReportsFalse() {
            let harness = makeUnsupportedAdapter()
            let adapter = harness.adapter

            #expect(adapter.isHardwareBacked == false)
        }

        @Test("concurrent attests over an unattested key generate one App Attest key, over 50 rounds")
        func concurrentAttestsGenerateOneKey() async {
            // Eight callers start `attest` together on one fresh adapter, and
            // Apple attests none of them, so the device must end up holding one
            // Secure Enclave App Attest key. This case fails when `attest`
            // stops routing key generation through `AppAttestCallSerializer`.
            // 50 rounds guard against a scheduler that happens to order one
            // round's callers one after another.
            for round in 0 ..< 50 {
                let defaults = InMemoryUserDefaults()
                let service = CountingAppAttestService()
                let adapter = AppleDeviceAttestation(
                    service: service,
                    defaults: defaults
                )

                await withTaskGroup(of: Void.self) { group in
                    for caller in 0 ..< 8 {
                        group.addTask {
                            _ = try? await adapter.attestReportingAttestationError(
                                challenge: Data(repeating: UInt8(caller), count: 32),
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
        private static let storedKeyId = Data(repeating: 0x06, count: 32).base64EncodedString()

        /// The key-probe input `K` of `09-security-model.md` §9.3.1, written
        /// out here instead of read from the adapter, so a change to the
        /// adapter's probe bytes fails a case.
        private static let keyProbeInput = Data(SHA256.hash(data: Data("SCP-APP-ATTEST-KEY-PROBE-V1".utf8)))

        /// An adapter under test, the defaults store it writes to, and the
        /// scripted service it calls.
        private struct ScriptedHarness {
            let adapter: AppleDeviceAttestation
            let defaults: InMemoryUserDefaults
            let service: ScriptedAppAttestService
        }

        /// Build an adapter over a scripted service and a defaults store that
        /// already holds `storedKeyId`.
        private func makeAdapter(
            attestScript: [Result<Data, Error>] = [.failure(ScriptedAppAttestService.invalidKeyError)],
            assertScript: [Result<Data, Error>] = [.failure(ScriptedAppAttestService.invalidKeyError)],
            attested: Bool
        ) -> ScriptedHarness {
            let defaults = InMemoryUserDefaults()
            defaults.set(Self.storedKeyId, forKey: Self.keyIdStorageKey)
            if attested {
                defaults.set(Self.storedKeyId, forKey: Self.attestedKeyIdStorageKey)
            }
            let service = ScriptedAppAttestService(
                attestScript: attestScript,
                assertScript: assertScript
            )
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)
            return ScriptedHarness(adapter: adapter, defaults: defaults, service: service)
        }

        @Test("attest reports keyAlreadyAttested, keeps and records the key, when the probe assertion succeeds")
        func attestProbeFindsAlreadyAttestedKey() async throws {
            // Apple attested the stored key but this adapter lost its record,
            // so `attestKey` answers `invalidKey`, and an assertion with that
            // key succeeds. Discarding it strands a live Secure Enclave key.
            let harness = makeAdapter(
                attestScript: [.failure(ScriptedAppAttestService.invalidKeyError), .success(Data([0xA7]))],
                assertScript: [.success(Data([0xB1]))],
                attested: false
            )

            do throws(AttestationError) {
                _ = try await harness.adapter.attestReportingAttestationError(
                    challenge: Data(repeating: 0x01, count: 32),
                    deviceId: Data([0x02])
                )
                Issue.record("attest returned bytes for a key Apple already attested")
            } catch {
                if case .keyAlreadyAttested = error {} else {
                    Issue.record("attest threw \(error) instead of AttestationError.keyAlreadyAttested")
                }
            }
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == Self.storedKeyId)
            #expect(harness.defaults.string(forKey: Self.attestedKeyIdStorageKey) == Self.storedKeyId)
            // The probe signs the key-probe input K of 09-security-model.md
            // §9.3.1, whose separator §9.18.2 registers, and never the
            // attestation's challenge, which is the binding digest D.
            #expect(harness.service.assertedClientDataHashes == [Self.keyProbeInput])
            #expect(!harness.service.assertedClientDataHashes.contains(Data(repeating: 0x01, count: 32)))

            // The record makes the next attest generate a replacement key.
            let bytes = try await harness.adapter.attestReportingAttestationError(
                challenge: Data(repeating: 0x02, count: 32),
                deviceId: Data([0x02])
            )
            #expect(bytes == Data([0xA7]))
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == ScriptedAppAttestService.generatedKeyId)
        }

        @Test("attest keeps the key and reports serverUnavailable when the probe assertion cannot reach Apple")
        func attestProbeServerUnavailableKeepsKey() async {
            // A caller retries on SCP-ATTEST-9024, so an outage during the
            // probe reports that code, and the kept key lets the retry succeed.
            let harness = makeAdapter(
                assertScript: [.failure(ScriptedAppAttestService.serverUnavailableError)],
                attested: false
            )

            do throws(AttestationError) {
                _ = try await harness.adapter.attestReportingAttestationError(
                    challenge: Data(repeating: 0x01, count: 32),
                    deviceId: Data([0x02])
                )
                Issue.record("attest returned bytes after attestKey answered invalidKey")
            } catch {
                if case .serverUnavailable = error {} else {
                    Issue.record("attest threw \(error) instead of AttestationError.serverUnavailable")
                }
            }
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == Self.storedKeyId)
            #expect(harness.defaults.string(forKey: Self.attestedKeyIdStorageKey) == nil)
            #expect(harness.service.assertedClientDataHashes == [Self.keyProbeInput])
        }

        @Test("attest keeps the key and reports serviceError when the probe assertion fails otherwise")
        func attestProbeFailureKeepsKey() async {
            let harness = makeAdapter(
                assertScript: [.failure(NSError(domain: "SCPTests", code: 1, userInfo: nil))],
                attested: false
            )

            do throws(AttestationError) {
                _ = try await harness.adapter.attestReportingAttestationError(
                    challenge: Data(repeating: 0x01, count: 32),
                    deviceId: Data([0x02])
                )
                Issue.record("attest returned bytes after attestKey answered invalidKey")
            } catch {
                if case .serviceError = error {} else {
                    Issue.record("attest threw \(error) instead of AttestationError.serviceError")
                }
            }
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == Self.storedKeyId)
            #expect(harness.defaults.string(forKey: Self.attestedKeyIdStorageKey) == nil)
            #expect(harness.service.assertedClientDataHashes == [Self.keyProbeInput])
        }

        @Test("attest generates a replacement key when the stored key is attested")
        func attestReplacesAttestedKey() async throws {
            let harness = makeAdapter(attestScript: [.success(Data([0xA1]))], attested: true)

            let bytes = try await harness.adapter.attestReportingAttestationError(
                challenge: Data(repeating: 0x01, count: 32),
                deviceId: Data([0x02])
            )

            // §9.3.1 keeps one attestation per context, and Apple attests one
            // key once, so a second context needs a second key.
            #expect(bytes == Data([0xA1]))
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == ScriptedAppAttestService.generatedKeyId)
            #expect(
                harness.defaults.string(forKey: Self.attestedKeyIdStorageKey) == ScriptedAppAttestService.generatedKeyId
            )
        }

        @Test("assertRequest keeps an attested key when Apple cannot reach its App Attest service")
        func assertRequestKeepsKeyOnServerUnavailable() async {
            let harness = makeAdapter(
                assertScript: [.failure(ScriptedAppAttestService.serverUnavailableError)],
                attested: true
            )

            do throws(AttestationError) {
                _ = try await harness.adapter.assertRequestReportingAttestationError(
                    requestHash: Data(repeating: 0xAB, count: 32)
                )
                Issue.record("assertRequest returned bytes while Apple's service was unavailable")
            } catch {
                if case .serverUnavailable = error {} else {
                    Issue.record("assertRequest threw \(error) instead of AttestationError.serverUnavailable")
                }
            }
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == Self.storedKeyId)
            #expect(harness.defaults.string(forKey: Self.attestedKeyIdStorageKey) == Self.storedKeyId)
        }

        @Test("assertRequest keeps an unattested key and reports that condition")
        func assertRequestKeepsUnattestedKey() async {
            let harness = makeAdapter(attested: false)

            await #expect(throws: AttestationError.self) {
                _ = try await harness.adapter.assertRequestReportingAttestationError(
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

            do throws(AttestationError) {
                _ = try await harness.adapter.assertRequestReportingAttestationError(
                    requestHash: Data(repeating: 0xAB, count: 32)
                )
                Issue.record("assertRequest returned bytes for an unattested key")
            } catch {
                guard case .keyNotAttested = error else {
                    Issue.record("assertRequest threw \(error) instead of AttestationError.keyNotAttested")
                    return
                }
            }
        }

        @Test("attest discards an unattested key Apple's service rejected")
        func attestDiscardsRejectedKey() async {
            let harness = makeAdapter(attested: false)

            do throws(AttestationError) {
                _ = try await harness.adapter.attestReportingAttestationError(
                    challenge: Data(repeating: 0x01, count: 32),
                    deviceId: Data([0x02])
                )
                Issue.record("attest returned bytes for a key Apple's service rejected")
            } catch {
                if case .keyRejected = error {} else {
                    Issue.record("attest threw \(error) instead of AttestationError.keyRejected")
                }
            }

            // `attestKey` and the probe assertion both answer `invalidKey`, so
            // Apple's service rejected this key. Keeping it would fail every
            // later `attest` against a dead key.
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == nil)
        }

        @Test("assertRequest discards an attested key Apple's service rejected")
        func assertRequestDiscardsRejectedKey() async {
            let harness = makeAdapter(attested: true)

            do throws(AttestationError) {
                _ = try await harness.adapter.assertRequestReportingAttestationError(
                    requestHash: Data(repeating: 0xAB, count: 32)
                )
                Issue.record("assertRequest returned bytes for a key Apple's service rejected")
            } catch {
                if case .keyRejected = error {} else {
                    Issue.record("assertRequest threw \(error) instead of AttestationError.keyRejected")
                }
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

            do throws(AttestationError) {
                _ = try await harness.adapter.attestReportingAttestationError(
                    challenge: Data(repeating: 0x01, count: 32),
                    deviceId: Data([0x02])
                )
                Issue.record("attest returned bytes while Apple's service was unavailable")
            } catch {
                guard case .serverUnavailable = error else {
                    Issue.record("attest threw \(error) instead of AttestationError.serverUnavailable")
                    return
                }
            }

            // `DCError.h` says to retry that attestation later using this same
            // key, because retrying with same inputs preserves a device's risk
            // metric.
            #expect(harness.defaults.string(forKey: Self.keyIdStorageKey) == Self.storedKeyId)
        }

        @Test("two attests in a row attest two keys, and an assertion reaches the second")
        func repeatedAttestReplacesKey() async throws {
            let defaults = InMemoryUserDefaults()
            let assertion = Data([0xAA, 0xBB])
            let service = ScriptedAppAttestService(
                attestScript: [.success(Data([0x01])), .success(Data([0x02]))],
                assertScript: [.success(assertion)]
            )
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

            let first = try await adapter.attestReportingAttestationError(
                challenge: Data(repeating: 0x01, count: 32),
                deviceId: Data([0x02])
            )
            #expect(first == Data([0x01]))
            #expect(defaults.string(forKey: Self.attestedKeyIdStorageKey) == ScriptedAppAttestService.generatedKeyId)

            // A second context needs its own attestation, and Apple attests one
            // key once, so this call must not hand Apple the attested key.
            let second = try await adapter.attestReportingAttestationError(
                challenge: Data(repeating: 0x03, count: 32),
                deviceId: Data([0x02])
            )
            #expect(second == Data([0x02]))
            #expect(service.keyGenerationCount == 2)
            #expect(defaults.string(forKey: Self.keyIdStorageKey) == ScriptedAppAttestService.secondGeneratedKeyId)
            #expect(
                defaults.string(forKey: Self.attestedKeyIdStorageKey) == ScriptedAppAttestService.secondGeneratedKeyId
            )
            let bytes = try await adapter.assertRequestReportingAttestationError(requestHash: Data(repeating: 0xAB, count: 32))
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
                service: service,
                defaults: defaults
            )

            // A first attestation generates a key and then fails to reach
            // Apple, so that key stays stored and unattested.
            _ = try? await adapter.attestReportingAttestationError(challenge: Data(repeating: 0x01, count: 32), deviceId: Data([0x02]))
            #expect(
                defaults.string(forKey: Self.keyIdStorageKey)
                    == ScriptedAppAttestService.generatedKeyId
            )

            // An assertion before that retry hits an unattested key. Discarding
            // that key here throws away what a retry needs.
            _ = try? await adapter.assertRequestReportingAttestationError(requestHash: Data(repeating: 0xAB, count: 32))
            #expect(
                defaults.string(forKey: Self.keyIdStorageKey)
                    == ScriptedAppAttestService.generatedKeyId
            )

            // Retrying that attestation with that same key succeeds.
            let bytes = try await adapter.attestReportingAttestationError(challenge: Data(repeating: 0x01, count: 32), deviceId: Data([0x02]))
            #expect(bytes == attestation)
            #expect(service.keyGenerationCount == 1)
        }

        @Test("a freshly generated key carries no attestation from a key it replaced")
        func generatedKeyCarriesNoStaleAttestation() async {
            let defaults = InMemoryUserDefaults()
            // A record naming the very key ID `generateKey` is about to hand
            // back, which a generated key must not inherit. Inheriting it would
            // classify the assertion below, over an unattested key, as a
            // rejected attested key and discard a key a retry needs.
            defaults.set(ScriptedAppAttestService.generatedKeyId, forKey: Self.attestedKeyIdStorageKey)
            let adapter = AppleDeviceAttestation(
                service: ScriptedAppAttestService(
                    attestScript: [.failure(ScriptedAppAttestService.serverUnavailableError)]
                ),
                defaults: defaults
            )

            _ = try? await adapter.attestReportingAttestationError(
                challenge: Data(repeating: 0x01, count: 32),
                deviceId: Data([0x02])
            )
            #expect(defaults.string(forKey: Self.attestedKeyIdStorageKey) == nil)

            do throws(AttestationError) {
                _ = try await adapter.assertRequestReportingAttestationError(requestHash: Data(repeating: 0xAB, count: 32))
                Issue.record("assertRequest returned bytes for an unattested key")
            } catch {
                if case .keyNotAttested = error {} else {
                    Issue.record("assertRequest threw \(error) instead of AttestationError.keyNotAttested")
                }
            }
            #expect(defaults.string(forKey: Self.keyIdStorageKey) == ScriptedAppAttestService.generatedKeyId)
        }
    }

    /// Cases that pin what a failed replacement attestation leaves in place.
    ///
    /// A key generated to replace an attested key is stored apart from it
    /// until Apple attests it, so `assertRequest` keeps naming the key an
    /// earlier published attestation names whatever the replacement's
    /// `attestKey` answers.
    struct AppAttestKeyReplacementTests {
        private static let keyIdStorageKey = "dev.limn.scp.appAttest.keyId"
        private static let attestedKeyIdStorageKey = "dev.limn.scp.appAttest.attestedKeyId"
        private static let replacementKeyIdStorageKey = "dev.limn.scp.appAttest.replacementKeyId"
        private static let storedKeyId = Data(repeating: 0x06, count: 32).base64EncodedString()

        @Test("a replacement attestation that cannot reach Apple leaves assertions on the attested key")
        func failedReplacementKeepsAttestedKey() async throws {
            let service = ScriptedAppAttestService(
                attestScript: [.failure(ScriptedAppAttestService.serverUnavailableError), .success(Data([0xA2]))],
                assertScript: [.success(Data([0xB1]))]
            )
            let defaults = InMemoryUserDefaults()
            defaults.set(Self.storedKeyId, forKey: Self.keyIdStorageKey)
            defaults.set(Self.storedKeyId, forKey: Self.attestedKeyIdStorageKey)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

            do throws(AttestationError) {
                _ = try await adapter.attestReportingAttestationError(
                    challenge: Data(repeating: 0x01, count: 32),
                    deviceId: Data([0x02])
                )
                Issue.record("attest returned bytes while Apple's service was unavailable")
            } catch {
                if case .serverUnavailable = error {} else {
                    Issue.record("attest threw \(error) instead of AttestationError.serverUnavailable")
                }
            }

            // The attested key an earlier published attestation names stays the
            // key assertions use, and the replacement waits for its retry.
            #expect(defaults.string(forKey: Self.keyIdStorageKey) == Self.storedKeyId)
            #expect(defaults.string(forKey: Self.attestedKeyIdStorageKey) == Self.storedKeyId)
            #expect(defaults.string(forKey: Self.replacementKeyIdStorageKey) == ScriptedAppAttestService.generatedKeyId)
            _ = try await adapter.assertRequestReportingAttestationError(requestHash: Data(repeating: 0xAB, count: 32))
            #expect(service.assertedKeyIds == [Self.storedKeyId])

            // The retry attests the same replacement key, which then becomes
            // the key assertions use.
            let bytes = try await adapter.attestReportingAttestationError(
                challenge: Data(repeating: 0x01, count: 32),
                deviceId: Data([0x02])
            )
            #expect(bytes == Data([0xA2]))
            #expect(service.keyGenerationCount == 1)
            #expect(defaults.string(forKey: Self.keyIdStorageKey) == ScriptedAppAttestService.generatedKeyId)
            #expect(defaults.string(forKey: Self.attestedKeyIdStorageKey) == ScriptedAppAttestService.generatedKeyId)
            #expect(defaults.string(forKey: Self.replacementKeyIdStorageKey) == nil)
        }

        @Test("a replacement key Apple's service rejects is discarded and the attested key stays")
        func rejectedReplacementKeepsAttestedKey() async throws {
            // `attestKey` and the probe assertion over the replacement both
            // answer `invalidKey`, and a later assertion succeeds.
            let service = ScriptedAppAttestService(
                attestScript: [.failure(ScriptedAppAttestService.invalidKeyError)],
                assertScript: [.failure(ScriptedAppAttestService.invalidKeyError), .success(Data([0xB1]))]
            )
            let defaults = InMemoryUserDefaults()
            defaults.set(Self.storedKeyId, forKey: Self.keyIdStorageKey)
            defaults.set(Self.storedKeyId, forKey: Self.attestedKeyIdStorageKey)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

            do throws(AttestationError) {
                _ = try await adapter.attestReportingAttestationError(
                    challenge: Data(repeating: 0x01, count: 32),
                    deviceId: Data([0x02])
                )
                Issue.record("attest returned bytes for a key Apple's service rejected")
            } catch {
                if case .keyRejected = error {} else {
                    Issue.record("attest threw \(error) instead of AttestationError.keyRejected")
                }
            }

            #expect(defaults.string(forKey: Self.keyIdStorageKey) == Self.storedKeyId)
            #expect(defaults.string(forKey: Self.attestedKeyIdStorageKey) == Self.storedKeyId)
            #expect(defaults.string(forKey: Self.replacementKeyIdStorageKey) == nil)
            let bytes = try await adapter.assertRequestReportingAttestationError(requestHash: Data(repeating: 0xAB, count: 32))
            #expect(bytes == Data([0xB1]))
            #expect(service.assertedKeyIds == [ScriptedAppAttestService.generatedKeyId, Self.storedKeyId])
        }

        @Test("a replacement key Apple already attested is discarded, and assertions stay on the attested key")
        func alreadyAttestedReplacementKeepsAttestedKey() async throws {
            // An earlier attest generated the replacement, Apple attested it,
            // and that call never returned its attestation object, for
            // example because the process ended first. So `attestKey` now
            // answers `invalidKey`, and the probe assertion succeeds. No
            // published attestation names the replacement.
            let replacementKeyId = Data(repeating: 0x08, count: 32).base64EncodedString()
            let service = ScriptedAppAttestService(
                attestScript: [.failure(ScriptedAppAttestService.invalidKeyError), .success(Data([0xA3]))],
                assertScript: [.success(Data([0xB0])), .success(Data([0xB1]))]
            )
            let defaults = InMemoryUserDefaults()
            defaults.set(Self.storedKeyId, forKey: Self.keyIdStorageKey)
            defaults.set(Self.storedKeyId, forKey: Self.attestedKeyIdStorageKey)
            defaults.set(replacementKeyId, forKey: Self.replacementKeyIdStorageKey)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

            do throws(AttestationError) {
                _ = try await adapter.attestReportingAttestationError(
                    challenge: Data(repeating: 0x01, count: 32),
                    deviceId: Data([0x02])
                )
                Issue.record("attest returned bytes for a key Apple already attested")
            } catch {
                if case .keyAlreadyAttested = error {} else {
                    Issue.record("attest threw \(error) instead of AttestationError.keyAlreadyAttested")
                }
            }

            #expect(defaults.string(forKey: Self.keyIdStorageKey) == Self.storedKeyId)
            #expect(defaults.string(forKey: Self.attestedKeyIdStorageKey) == Self.storedKeyId)
            #expect(defaults.string(forKey: Self.replacementKeyIdStorageKey) == nil)
            let bytes = try await adapter.assertRequestReportingAttestationError(requestHash: Data(repeating: 0xAB, count: 32))
            #expect(bytes == Data([0xB1]))
            #expect(service.assertedKeyIds == [replacementKeyId, Self.storedKeyId])

            // The next attest generates another replacement, which becomes
            // the stored key only when an attestation naming it returns.
            let attestation = try await adapter.attestReportingAttestationError(
                challenge: Data(repeating: 0x02, count: 32),
                deviceId: Data([0x02])
            )
            #expect(attestation == Data([0xA3]))
            #expect(defaults.string(forKey: Self.keyIdStorageKey) == ScriptedAppAttestService.generatedKeyId)
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

        @Test("a second attest racing a first attests a replacement key rather than the first key")
        func concurrentAttestReplacesAttestedKey() async {
            // Apple answers a first `attestKey` after a round trip. A second
            // caller that reads the stored key before the first caller records
            // its attestation hands Apple that same key again, which Apple
            // attests once.
            let defaults = InMemoryUserDefaults()
            let service = OverlapDetectingAppAttestService(
                attestScript: [
                    .init(result: .success(Data([0xA1, 0xA2])), delay: 0.20),
                    .init(result: .success(Data([0xC1])), delay: 0)
                ],
                assertScript: [.init(result: .success(Data([0xB1])), delay: 0)]
            )
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

            async let first = adapter.attestReportingAttestationError(
                challenge: Data(repeating: 0x01, count: 32),
                deviceId: Data([0x02])
            )
            // Wait until a first caller reaches `attestKey`, whose answer takes
            // 200 ms, before a second caller starts, so a second caller takes
            // a second scripted answer. Bounded, so a first caller that never
            // reaches Apple fails this case instead of hanging the suite.
            var waitedMilliseconds = 0
            while service.attestedKeyIds.isEmpty, waitedMilliseconds < 10000 {
                try? await Task.sleep(nanoseconds: 1_000_000)
                waitedMilliseconds += 1
            }
            #expect(!service.attestedKeyIds.isEmpty, "the first attest never reached attestKey")
            async let second = adapter.attestReportingAttestationError(
                challenge: Data(repeating: 0x03, count: 32),
                deviceId: Data([0x04])
            )

            let firstOutcome = try? await first
            let secondOutcome = try? await second
            #expect(firstOutcome == Data([0xA1, 0xA2]))
            #expect(secondOutcome == Data([0xC1]))
            #expect(
                defaults.string(forKey: Self.keyIdStorageKey) == OverlapDetectingAppAttestService.generatedKeyId(1),
                "a racing attest reused a key Apple had attested"
            )
            #expect(
                defaults.string(forKey: Self.attestedKeyIdStorageKey) == OverlapDetectingAppAttestService.generatedKeyId(1)
            )
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
                service: service,
                defaults: defaults
            )

            // One attestation first, so every assertion below finds a stored
            // key ID rather than throwing `keyNotFound` before it calls out.
            _ = try? await adapter.attestReportingAttestationError(challenge: Data(repeating: 0x00, count: 32), deviceId: Data([0x01]))

            await withTaskGroup(of: Void.self) { group in
                for caller in 0 ..< 3 {
                    group.addTask {
                        _ = try? await adapter.attestReportingAttestationError(
                            challenge: Data(repeating: UInt8(caller), count: 32),
                            deviceId: Data([0x02])
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

        @Test("every adapter built with init() shares one lock and one serializer")
        func standardAdaptersShareKeyState() {
            // Every such adapter reads `UserDefaults.standard`, which the
            // process shares, so its App Attest calls have to run in one order
            // with every other such adapter's calls.
            #expect(AppleDeviceAttestation().sharesKeyState(with: AppleDeviceAttestation()))
        }

        @Test("two adapters over one defaults store never hand Apple one key twice")
        func adaptersSharingDefaultsAttestEachKeyOnce() async {
            // Both adapters read the stored, unattested key. Unless they share
            // one serializer, both hand Apple that key, which Apple attests
            // once, and App Attest sees two outstanding calls.
            let storedKeyId = Data(repeating: 0x06, count: 32).base64EncodedString()
            let defaults = InMemoryUserDefaults()
            defaults.set(storedKeyId, forKey: Self.keyIdStorageKey)
            let service = OverlapDetectingAppAttestService(
                attestScript: [.init(result: .success(Data([0xA1])), delay: 0.10)],
                assertScript: [.init(result: .success(Data([0xB1])), delay: 0)]
            )
            let first = AppleDeviceAttestation(service: service, defaults: defaults)
            let second = AppleDeviceAttestation(service: service, defaults: defaults, sharingKeyStateWith: first)

            await withTaskGroup(of: Void.self) { group in
                for adapter in [first, second] {
                    group.addTask {
                        _ = try? await adapter.attestReportingAttestationError(
                            challenge: Data(repeating: 0x01, count: 32),
                            deviceId: Data([0x02])
                        )
                    }
                }
            }

            #expect(first.sharesKeyState(with: second))
            #expect(service.peakConcurrency == 1)
            #expect(service.attestedKeyIds.count == 2)
            #expect(Set(service.attestedKeyIds).count == 2, "Apple was asked to attest one key twice")
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

            let first = try await adapter.attestReportingAttestationError(challenge: challenge, deviceId: Data([0xFF, 0xEE]))
            let second = try await adapter.attestReportingAttestationError(challenge: challenge, deviceId: Data([0x01]))

            #expect(first == Data([0xA1]))
            #expect(second == Data([0xA1]))
            let call = RecordingAppAttestService.Call(
                keyId: RecordingAppAttestService.generatedKeyId,
                clientDataHash: challenge
            )
            #expect(service.attestations == [call, call])
        }

        @Test("attest rejects a challenge that is not 32 bytes before it generates a key or calls Apple")
        func attestRejectsWrongLengthChallenge() async {
            for length in [0, 31, 33] {
                let service = RecordingAppAttestService()
                let defaults = InMemoryUserDefaults()
                let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

                do throws(ScpError) {
                    _ = try await adapter.attest(challenge: Data(repeating: 0x01, count: length), deviceId: Data([0x02]))
                    Issue.record("attest returned bytes for a \(length)-byte challenge")
                } catch {
                    guard case let .Identity(_, code) = error else {
                        Issue.record("attest threw \(error) instead of ScpError.Identity")
                        continue
                    }
                    #expect(code == "SCP-ATTEST-9026")
                }
                #expect(defaults.string(forKey: "dev.limn.scp.appAttest.keyId") == nil)
                #expect(service.attestations.isEmpty)
                #expect(service.assertions.isEmpty)
            }
        }

        @Test("assertRequest rejects a requestHash that is not 32 bytes before it calls Apple")
        func assertRequestRejectsWrongLengthRequestHash() async throws {
            for length in [0, 31, 33, 57] {
                let service = RecordingAppAttestService()
                let adapter = AppleDeviceAttestation(service: service, defaults: InMemoryUserDefaults())
                _ = try await adapter.attestReportingAttestationError(
                    challenge: Data(repeating: 0x01, count: 32),
                    deviceId: Data([0x02])
                )

                do throws(ScpError) {
                    _ = try await adapter.assertRequest(requestHash: Data(repeating: 0x01, count: length))
                    Issue.record("assertRequest returned bytes for a \(length)-byte requestHash")
                } catch {
                    guard case let .Identity(_, code) = error else {
                        Issue.record("assertRequest threw \(error) instead of ScpError.Identity")
                        continue
                    }
                    #expect(code == "SCP-ATTEST-9026")
                }
                #expect(service.assertions.isEmpty)
            }
        }

        @Test("assertRequest hands Apple requestHash unchanged")
        func assertRequestForwardsRequestHash() async throws {
            let service = RecordingAppAttestService()
            let adapter = AppleDeviceAttestation(service: service, defaults: InMemoryUserDefaults())
            _ = try await adapter.attestReportingAttestationError(challenge: Data(repeating: 0x01, count: 32), deviceId: Data([0x02]))

            let requestHash = Data((0 ..< 32).map { UInt8($0) })
            _ = try await adapter.assertRequestReportingAttestationError(requestHash: requestHash)

            #expect(
                service.assertions == [
                    .init(keyId: RecordingAppAttestService.generatedKeyId, clientDataHash: requestHash)
                ]
            )
        }

        @Test("a queued assertion reads the key ID after its predecessor discarded it")
        func queuedAssertionReadsKeyIdAfterPredecessor() async throws {
            let service = RecordingAppAttestService(
                holdsFirstAssertion: true,
                assertionResult: .failure(RecordingAppAttestService.invalidKeyError)
            )
            let defaults = InMemoryUserDefaults()
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)
            _ = try await adapter.attestReportingAttestationError(challenge: Data(repeating: 0x01, count: 32), deviceId: Data([0x02]))

            // The first assertion reaches Apple and waits there. Apple then
            // rejects that attested key, so the adapter discards its key ID.
            let first = Task { try await adapter.assertRequestReportingAttestationError(requestHash: Data(repeating: 0x01, count: 32)) }
            // Bounded, so an assertion that fails before reaching Apple fails
            // this case instead of hanging the suite.
            var waitedMilliseconds = 0
            while !service.isHoldingAssertion {
                guard waitedMilliseconds < 10000 else {
                    Issue.record("the first assertion never reached generateAssertion")
                    first.cancel()
                    return
                }
                try await Task.sleep(nanoseconds: 1_000_000)
                waitedMilliseconds += 1
            }
            // The second assertion arrives while the first is outstanding. An
            // adapter that read the key ID before queueing would hand Apple the
            // discarded key ID and report `keyNotAttested` for a key it no
            // longer stores.
            let second = Task { try await adapter.assertRequestReportingAttestationError(requestHash: Data(repeating: 0x02, count: 32)) }
            try await Task.sleep(nanoseconds: 50_000_000)
            service.releaseHeldAssertion()

            do {
                _ = try await first.value
                Issue.record("the first assertion returned bytes for a rejected key")
            } catch let error as AttestationError {
                guard case .keyRejected = error else {
                    Issue.record("the first assertion threw \(error) instead of keyRejected")
                    return
                }
            }
            do {
                _ = try await second.value
                Issue.record("the second assertion returned bytes with no stored key")
            } catch let error as AttestationError {
                guard case .keyNotFound = error else {
                    Issue.record("the second assertion threw \(error) instead of keyNotFound")
                    return
                }
            }
            #expect(service.assertions.count == 1)
        }
    }

    // MARK: - Incomplete App Attest answers

    /// A `DCAppAttestService` whose completion handlers answer with neither a
    /// value nor an error.
    private final class SilentAppAttestService: DCAppAttestService, @unchecked Sendable {
        /// A key ID `generateKey` hands back when `answersKeyGeneration` is set.
        static let generatedKeyId = Data(repeating: 0x09, count: 32).base64EncodedString()

        private let answersKeyGeneration: Bool

        init(answersKeyGeneration: Bool) {
            self.answersKeyGeneration = answersKeyGeneration
            super.init()
        }

        override var isSupported: Bool {
            true
        }

        override func generateKey(completionHandler: @escaping (String?, Error?) -> Void) {
            completionHandler(answersKeyGeneration ? Self.generatedKeyId : nil, nil)
        }

        override func attestKey(
            _: String,
            clientDataHash _: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            completionHandler(nil, nil)
        }

        override func generateAssertion(
            _: String,
            clientDataHash _: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            completionHandler(nil, nil)
        }
    }

    /// Cases that pin `SCP-ATTEST-9025`, which the adapter throws when an App
    /// Attest completion handler answers with neither a value nor an error,
    /// so the adapter returns no bytes and stores no key ID it did not receive.
    struct AppAttestIncompleteAnswerTests {
        private static let keyIdStorageKey = "dev.limn.scp.appAttest.keyId"
        private static let attestedKeyIdStorageKey = "dev.limn.scp.appAttest.attestedKeyId"

        /// Require that `error` is `ScpError.Identity` with code `SCP-ATTEST-9025`.
        private func expectInternalError(_ error: ScpError, from method: String) {
            guard case let .Identity(_, code) = error else {
                Issue.record("\(method) threw \(error) instead of ScpError.Identity")
                return
            }
            #expect(code == "SCP-ATTEST-9025")
        }

        @Test("attest throws SCP-ATTEST-9025 and stores no key ID when generateKey answers with nothing")
        func attestRejectsEmptyKeyGeneration() async {
            let defaults = InMemoryUserDefaults()
            let adapter = AppleDeviceAttestation(
                service: SilentAppAttestService(answersKeyGeneration: false),
                defaults: defaults
            )

            do throws(ScpError) {
                _ = try await adapter.attest(challenge: Data(repeating: 0x01, count: 32), deviceId: Data([0x02]))
                Issue.record("attest returned bytes when generateKey answered with nothing")
            } catch {
                expectInternalError(error, from: "attest")
            }
            #expect(defaults.string(forKey: Self.keyIdStorageKey) == nil)
        }

        @Test("attest throws SCP-ATTEST-9025 and records no attestation when attestKey answers with nothing")
        func attestRejectsEmptyAttestation() async {
            let defaults = InMemoryUserDefaults()
            let adapter = AppleDeviceAttestation(
                service: SilentAppAttestService(answersKeyGeneration: true),
                defaults: defaults
            )

            do throws(ScpError) {
                _ = try await adapter.attest(challenge: Data(repeating: 0x01, count: 32), deviceId: Data([0x02]))
                Issue.record("attest returned bytes when attestKey answered with nothing")
            } catch {
                expectInternalError(error, from: "attest")
            }
            #expect(defaults.string(forKey: Self.keyIdStorageKey) == SilentAppAttestService.generatedKeyId)
            #expect(defaults.string(forKey: Self.attestedKeyIdStorageKey) == nil)
        }

        @Test("assertRequest throws SCP-ATTEST-9025 when generateAssertion answers with nothing")
        func assertRequestRejectsEmptyAssertion() async {
            let defaults = InMemoryUserDefaults()
            defaults.set(SilentAppAttestService.generatedKeyId, forKey: Self.keyIdStorageKey)
            defaults.set(SilentAppAttestService.generatedKeyId, forKey: Self.attestedKeyIdStorageKey)
            let adapter = AppleDeviceAttestation(
                service: SilentAppAttestService(answersKeyGeneration: true),
                defaults: defaults
            )

            do throws(ScpError) {
                _ = try await adapter.assertRequest(requestHash: Data(repeating: 0xAB, count: 32))
                Issue.record("assertRequest returned bytes when generateAssertion answered with nothing")
            } catch {
                expectInternalError(error, from: "assertRequest")
            }
            #expect(defaults.string(forKey: Self.keyIdStorageKey) == SilentAppAttestService.generatedKeyId)
        }
    }

#endif // os(iOS) || os(macOS)
