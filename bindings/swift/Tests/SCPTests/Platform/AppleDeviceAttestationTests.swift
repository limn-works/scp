// Fail-closed, key-lifecycle, and call-ordering tests for adapter
// `AppleDeviceAttestation`.
//
// These tests pin four properties of `AppleDeviceAttestation`:
//
// 1. When `DCAppAttestService.isSupported` is `false`, `attest` and
//    `assertRequest` throw `ScpError` code `SCP-ATTEST-9019`, the type the
//    UniFFI callback declares, and return no bytes.
//    §9.3 of SCP's security model spec, "Sybil resistance and identity
//    uniqueness", states that the absence of a device attestation is expected
//    and is not penalizing, so a typed error is an honest result and a
//    locally minted token would assert a hardware guarantee no hardware
//    produced.
// 2. Concurrent first calls to `attest` generate one App Attest key.
//    `AppAttestCallSerializer` runs each `attest` body after the previous body
//    finished, so the first caller stores its key ID before a second caller
//    reads one. These cases drive `attest` through that serializer and so pin
//    that outcome. No case here runs two callers inside `resolveKeyId` at
//    once, so no case here fails when `resolveKeyId` reads absence in one
//    critical section and publishes its generation task in another.
// 3. Concurrent calls reach Apple's App Attest service one at a time, and a
//    second `attest` therefore keeps the key a first `attest` got attested
//    rather than reading a stale attestation record and discarding that key.
//    Each queued call also reads the stored key ID after its predecessors
//    finished, so it never names a key ID a predecessor discarded.
// 4. `attest` hands Apple `SHA-256` of the exact `clientDataJSON` bytes
//    acceptance criterion 3 of ADR-025 fixes, and `assertRequest` hands Apple
//    `requestHash` unchanged. Clause 6 of that criterion makes a reader rebuild
//    those bytes, so a change to field order, encoding, or type string turns a
//    case here red.
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
            completionHandler(Data(repeating: 0x02, count: 32).base64EncodedString(), nil)
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
        static let generatedKeyId = Data(repeating: 0x03, count: 32).base64EncodedString()

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
        static let generatedKeyId = Data(repeating: 0x04, count: 32).base64EncodedString()

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

    /// A `DCAppAttestService` that records the key ID and the
    /// `clientDataHash` of every call, and can hold its first assertion until
    /// a case releases it.
    ///
    /// Every other double here ignores `clientDataHash`, so none of them
    /// notices a change to the bytes `attest` and `assertRequest` hand Apple.
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
        /// Rust receives. Rust's half of that path is
        /// `device_attestation_callback_scp_error_lifts_to_an_error_value` in
        /// `crates/scp-ffi/uniffi/src/lib.rs`.
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
                    challenge: Data([0x01, 0x02, 0x03]),
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
                .keyNotAttested("m"), .keyRejected("m"), .serverUnavailable("m"), .internalError("m")
            ]
            let codes = cases.compactMap { error -> String? in
                guard case let .Identity(_, code) = error.scpError else { return nil }
                return code
            }
            let expected = ["9001", "9019", "9020", "9021", "9022", "9023", "9024", "9025"]
            #expect(codes == expected.map { "SCP-ATTEST-\($0)" })
        }

        @Test("a failed attest stores no App Attest key ID")
        func failedAttestStoresNoKeyId() async {
            let harness = makeUnsupportedAdapter()
            let adapter = harness.adapter

            _ = try? await adapter.attestReportingAttestationError(challenge: Data([0x01]), deviceId: Data([0x02]))

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
            // Eight callers start `attest` together on one fresh adapter, and
            // the device must end up holding one Secure Enclave App Attest key.
            // This case fails when `attest` stops routing its body through
            // `AppAttestCallSerializer` and `resolveKeyId` also lets a second
            // caller read absence. It does not fail for a split inside
            // `resolveKeyId` alone, because the serializer admits one caller
            // to `resolveKeyId` at a time. 50 rounds guard against a scheduler
            // that happens to order one round's callers one after another.
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
        private static let storedKeyId = Data(repeating: 0x06, count: 32).base64EncodedString()

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
                _ = try await harness.adapter.attestReportingAttestationError(
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
                _ = try await harness.adapter.attestReportingAttestationError(
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

            do {
                _ = try await harness.adapter.assertRequestReportingAttestationError(
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
                _ = try await harness.adapter.attestReportingAttestationError(
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
                _ = try await harness.adapter.assertRequestReportingAttestationError(
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
                _ = try await harness.adapter.attestReportingAttestationError(
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
                service: service,
                defaults: defaults
            )

            // First attestation succeeds and records which key Apple attested.
            _ = try await adapter.attestReportingAttestationError(challenge: Data([0x01]), deviceId: Data([0x02]))
            let keyIdAfterFirst = defaults.string(forKey: Self.keyIdStorageKey)
            #expect(keyIdAfterFirst == ScriptedAppAttestService.generatedKeyId)
            #expect(
                defaults.string(forKey: Self.attestedKeyIdStorageKey)
                    == ScriptedAppAttestService.generatedKeyId
            )

            // A second attestation is an ordinary call, because a server
            // challenge is single-use. Apple answers `invalidKey` for it.
            await #expect(throws: AttestationError.self) {
                _ = try await adapter.attestReportingAttestationError(challenge: Data([0x03]), deviceId: Data([0x02]))
            }

            // That second call must leave one key alive: discarding it here
            // burns one Secure Enclave key per two `attest` calls, and leaves
            // `assertRequest` throwing `keyNotFound` over a key that still
            // exists.
            #expect(defaults.string(forKey: Self.keyIdStorageKey) == keyIdAfterFirst)
            #expect(service.keyGenerationCount == 1)
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
            _ = try? await adapter.attestReportingAttestationError(challenge: Data([0x01]), deviceId: Data([0x02]))
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
            let bytes = try await adapter.attestReportingAttestationError(challenge: Data([0x01]), deviceId: Data([0x02]))
            #expect(bytes == Data(repeating: 0x03, count: 32) + attestation)
            #expect(service.keyGenerationCount == 1)
        }

        @Test("a key ID that is not 32 base64-decoded bytes fails before Apple attests it")
        func malformedKeyIdFailsBeforeAttestKey() async {
            let defaults = InMemoryUserDefaults()
            defaults.set("not-a-32-byte-key-id", forKey: Self.keyIdStorageKey)
            let adapter = AppleDeviceAttestation(
                service: ScriptedAppAttestService(attestScript: [.success(Data([0x04]))]),
                defaults: defaults
            )

            do throws(AttestationError) {
                _ = try await adapter.attestReportingAttestationError(challenge: Data([0x01]), deviceId: Data([0x02]))
                Issue.record("attest returned a token for a key ID it cannot carry")
            } catch {
                guard case .internalError = error else {
                    Issue.record("attest threw \(error) instead of AttestationError.internalError")
                    return
                }
            }
            // A successful `attestKey` records its key as attested, so an empty
            // record shows this call never reached Apple.
            #expect(defaults.string(forKey: Self.attestedKeyIdStorageKey) == nil)
        }

        @Test("a freshly generated key carries no attestation from a key it replaced")
        func generatedKeyCarriesNoStaleAttestation() async {
            let defaults = InMemoryUserDefaults()
            // A record left by a previous key, which a generated key must not
            // inherit: inheriting it would classify a rejected key as already
            // attested and keep a dead key ID forever.
            defaults.set("previous-key-id", forKey: Self.attestedKeyIdStorageKey)
            let adapter = AppleDeviceAttestation(
                service: ScriptedAppAttestService(),
                defaults: defaults
            )

            _ = try? await adapter.attestReportingAttestationError(challenge: Data([0x01]), deviceId: Data([0x02]))

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
                service: service,
                defaults: defaults
            )

            async let first = adapter.attestReportingAttestationError(challenge: Data([0x01]), deviceId: Data([0x02]))
            // Let a first caller reach `attestKey` before a second caller
            // starts, so a second caller takes a second scripted answer.
            try? await Task.sleep(nanoseconds: 50_000_000)
            async let second = adapter.attestReportingAttestationError(challenge: Data([0x03]), deviceId: Data([0x04]))

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

            #expect(firstOutcome == Data(repeating: 0x04, count: 32) + Data([0xA1, 0xA2]))
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
                service: service,
                defaults: defaults
            )

            // One attestation first, so every assertion below finds a stored
            // key ID rather than throwing `keyNotFound` before it calls out.
            _ = try? await adapter.attestReportingAttestationError(challenge: Data([0x00]), deviceId: Data([0x01]))

            await withTaskGroup(of: Void.self) { group in
                for caller in 0 ..< 3 {
                    group.addTask {
                        _ = try? await adapter.attestReportingAttestationError(
                            challenge: Data([UInt8(caller)]),
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
    }

    // MARK: - Client data tests

    /// Cases that pin the bytes `AppleDeviceAttestation` hands Apple.
    struct AppAttestClientDataTests {
        @Test("attest hands Apple SHA-256 of the clientDataJSON ADR-025 fixes")
        func attestHashesTheFixedClientDataJSON() async throws {
            let service = RecordingAppAttestService()
            let adapter = AppleDeviceAttestation(service: service, defaults: InMemoryUserDefaults())

            _ = try await adapter.attestReportingAttestationError(challenge: Data([0x01, 0x02, 0x03]), deviceId: Data([0xFF, 0xEE]))

            // RFC 4648 base64 of 0x010203 is `AQID`, and of 0xFFEE is `/+4=`.
            // This literal restates acceptance criterion 3 of ADR-025 rather
            // than calling the adapter's own formula, so a change to that
            // formula turns this case red.
            let expectedJSON = #"{"challenge":"AQID","deviceId":"/+4=","type":"scp-device-attestation-v1"}"#
            let expectedHash = Data(SHA256.hash(data: Data(expectedJSON.utf8)))
            #expect(
                service.attestations == [
                    .init(keyId: RecordingAppAttestService.generatedKeyId, clientDataHash: expectedHash)
                ]
            )
        }

        @Test("assertRequest hands Apple requestHash unchanged")
        func assertRequestForwardsRequestHash() async throws {
            let service = RecordingAppAttestService()
            let adapter = AppleDeviceAttestation(service: service, defaults: InMemoryUserDefaults())
            _ = try await adapter.attestReportingAttestationError(challenge: Data([0x01]), deviceId: Data([0x02]))

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
            _ = try await adapter.attestReportingAttestationError(challenge: Data([0x01]), deviceId: Data([0x02]))

            // The first assertion reaches Apple and waits there. Apple then
            // rejects that attested key, so the adapter discards its key ID.
            let first = Task { try await adapter.assertRequestReportingAttestationError(requestHash: Data(repeating: 0x01, count: 32)) }
            while !service.isHoldingAssertion {
                try await Task.sleep(nanoseconds: 1_000_000)
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

#endif // os(iOS) || os(macOS)
