// Tests for adapter `AppleDeviceAttestation`.
//
// These tests pin six properties of `AppleDeviceAttestation`:
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
// 5. While every call ends with Apple's answer, App Attest sees one
//    outstanding call at a time: a call queued behind a running call reaches
//    Apple only after that call ends, concurrent `attest` calls on a device
//    with no stored key generate one key, and every adapter over one
//    `UserDefaults` object shares one lock and one call serializer. A call that the `isSupported` check or the 32-byte
//    check rejects returns while another call holds the serializer, so it
//    never waits in the queue. A call Apple does not answer within the
//    adapter's time limit throws `SCP-ATTEST-9027` and the next queued call
//    runs while Apple may still hold the abandoned call; Apple's later
//    answer stores no key ID and reaches no caller. A caller cancelled while
//    queued never reaches Apple, and one cancelled while Apple holds its
//    call frees the queue. A cancellation that arrives while the adapter
//    stores a generated key ID ends the call only after the `attestKey` that
//    step leads to started; a cancellation during the key-ID read, or
//    before the call starts, ends the call before it hands App Attest any
//    method, so a call never starts a method after it ended.
//    `AppAttestCallEndTests` pins those cases. `AppAttestCallOrderingTests`
//    pins each other case: the
//    time-out case injects a limit of one second and the late-answer case
//    one of 300 milliseconds in place of the adapter's 25 seconds, the
//    cancellation cases keep the 25-second default and cancel well before it
//    expires, and one case asserts the default is 25 seconds.
// 6. When `attestKey` returns an attestation object, the adapter records
//    that key ID as attested, and a later `attest` generates and attests a
//    replacement key, which becomes the stored key only when its attestation
//    returns. `DCError.invalidKey` from
//    `assertRequest`'s `generateAssertion` keeps a key with no record
//    (`SCP-ATTEST-9022`) and discards a recorded key's ID and record
//    (`SCP-ATTEST-9023`);
//    `DCError.serverUnavailable` from `attestKey` or `generateAssertion`
//    keeps the key (`SCP-ATTEST-9024`). `DCError.invalidKey` from
//    `attestKey` leads to the key probe, an assertion over the key-probe
//    input `K` of §9.3.1 of the security model spec, and each probe answer
//    gives its own code: an assertion records the stored key, or discards
//    a replacement key, and throws `SCP-ATTEST-9021`, `DCError.invalidKey`
//    discards the key (`SCP-ATTEST-9023`), and every other answer keeps it.
//    An answer that arrives after its call ended writes no record, discards
//    no key ID, and starts no key probe. `AppAttestKeyLifecycleTests` pins
//    each case, and `AppAttestKeyReplacementTests` pins that a failed,
//    rejected or already-attested replacement leaves `assertRequest` on the
//    attested key.
//
// See ADR-025 (Apple Platform Adapter) in `.docs/adrs/phase-5.md` and the
// UniFFI `DeviceAttestationProvider` callback interface in
// `crates/scp-ffi/uniffi/src/lib.rs`, which the adapter conforms to.

#if os(iOS) || os(macOS)

    import CryptoKit
    import DeviceCheck
    import Foundation
    import os
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

    /// The `UserDefaults` key `AppleDeviceAttestation` stores the ID of a key
    /// Apple attested under.
    private let attestedKeyIdDefaultsKey = "dev.limn.scp.appAttest.attestedKeyId"

    /// The `UserDefaults` key `AppleDeviceAttestation` stores the ID of a key
    /// generated to replace an attested key under, until Apple attests it.
    private let replacementKeyIdDefaultsKey = "dev.limn.scp.appAttest.replacementKeyId"

    /// A stored key ID other than any key ID a scripted `generateKey` answers
    /// with, so a case tells the stored key apart from a generated one.
    private let storedKeyId = "stored-app-attest-key"

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
        /// `DCError.invalidKey` and no value, the code `DCError.h` gives for
        /// an already-attested key, an unattested key and a rejected key.
        case invalidKey
        /// `DCError.serverUnavailable` and no value, the code `DCError.h`
        /// gives `attestKey` for a failed attempt to contact App Attest.
        case serverUnavailable

        func deliver(to handler: (Value?, Error?) -> Void) {
            switch self {
            case let .value(value): handler(value, nil)
            case .failure: handler(nil, NSError(domain: "AppleDeviceAttestationTests", code: 1))
            case .featureUnsupported: handler(nil, DCError(.featureUnsupported))
            case .neither: handler(nil, nil)
            case .invalidKey: handler(nil, NSError(domain: DCErrorDomain, code: DCError.invalidKey.rawValue))
            case .serverUnavailable: handler(nil, NSError(domain: DCErrorDomain, code: DCError.serverUnavailable.rawValue))
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
    /// App Attest receives, and counts the calls of each method.
    /// `thenKey`, `thenAttestation` and `thenAssertion`, when set, answer
    /// every `generateKey`, `attestKey` and `generateAssertion` call after the
    /// first.
    private final class ScriptedAppAttestService: DCAppAttestService {
        private let reportsSupport: Bool
        private let lock = NSLock()
        private var attestKeyArguments: (keyId: String, clientDataHash: Data)?
        private var generateAssertionArguments: (keyId: String, clientDataHash: Data)?
        private var attestKeyIds: [String] = []
        private var assertionKeyIds: [String] = []
        private var keyGenerations = 0
        private var attestKeyCalls = 0
        private var generateAssertionCalls = 0

        /// How many times `generateKey` ran.
        var keyGenerationCount: Int {
            lock.withLock { keyGenerations }
        }

        /// How many times `attestKey` ran.
        var attestKeyCount: Int {
            lock.withLock { attestKeyCalls }
        }

        /// How many times `generateAssertion` ran.
        var generateAssertionCount: Int {
            lock.withLock { generateAssertionCalls }
        }

        /// The key ID of the last `attestKey` call, or `nil` if none was made.
        var attestKeyKeyId: String? {
            lock.withLock { attestKeyArguments?.keyId }
        }

        /// The key ID and `clientDataHash` of the last `generateAssertion`
        /// call, or `nil` if none was made.
        var generateAssertionCall: (keyId: String, clientDataHash: Data)? {
            lock.withLock { generateAssertionArguments }
        }

        /// The key ID of every `attestKey` call, in arrival order.
        var attestedKeyIds: [String] {
            lock.withLock { attestKeyIds }
        }

        /// The key ID of every `generateAssertion` call, in arrival order.
        var assertedKeyIds: [String] {
            lock.withLock { assertionKeyIds }
        }

        private let key: Answer<String>
        private let thenKey: Answer<String>?
        private let attestation: Answer<Data>
        private let thenAttestation: Answer<Data>?
        private let assertion: Answer<Data>
        private let thenAssertion: Answer<Data>?

        init(
            supported: Bool,
            key: Answer<String> = .value(scriptedKeyId),
            thenKey: Answer<String>? = nil,
            attestation: Answer<Data> = .value(scriptedAttestation),
            thenAttestation: Answer<Data>? = nil,
            assertion: Answer<Data> = .value(scriptedAssertion),
            thenAssertion: Answer<Data>? = nil
        ) {
            reportsSupport = supported
            self.key = key
            self.thenKey = thenKey
            self.attestation = attestation
            self.thenAttestation = thenAttestation
            self.assertion = assertion
            self.thenAssertion = thenAssertion
            super.init()
        }

        override var isSupported: Bool {
            reportsSupport
        }

        override func generateKey(completionHandler: @escaping (String?, Error?) -> Void) {
            let ordinal: Int = lock.withLock {
                keyGenerations += 1
                return keyGenerations
            }
            let answer = ordinal > 1 ? thenKey ?? key : key
            answer.deliver(to: completionHandler)
        }

        override func attestKey(
            _ keyId: String,
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            let ordinal: Int = lock.withLock {
                attestKeyArguments = (keyId, clientDataHash)
                attestKeyIds.append(keyId)
                attestKeyCalls += 1
                return attestKeyCalls
            }
            let answer = ordinal > 1 ? thenAttestation ?? attestation : attestation
            answer.deliver(to: completionHandler)
        }

        override func generateAssertion(
            _ keyId: String,
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            let ordinal: Int = lock.withLock {
                generateAssertionArguments = (keyId, clientDataHash)
                assertionKeyIds.append(keyId)
                generateAssertionCalls += 1
                return generateAssertionCalls
            }
            let answer = ordinal > 1 ? thenAssertion ?? assertion : assertion
            answer.deliver(to: completionHandler)
        }
    }

    /// A `DCAppAttestService` that reports App Attest as available, counts how
    /// many times a caller asked it to generate a key, records the key ID and
    /// `clientDataHash` of every `attestKey` call, and answers every
    /// `attestKey` with an error.
    private final class CountingAppAttestService: DCAppAttestService {
        /// A key ID this double hands back to every caller.
        static let keyId = Data(repeating: 0x01, count: 32).base64EncodedString()

        private let lock = NSLock()
        private var callCount = 0
        private var attestKeyArguments: [(keyId: String, clientDataHash: Data)] = []

        /// How many times `generateKey` ran.
        var keyGenerationCount: Int {
            lock.withLock { callCount }
        }

        /// The key ID and `clientDataHash` of every `attestKey` call, in
        /// arrival order.
        var attestKeyCalls: [(keyId: String, clientDataHash: Data)] {
            lock.withLock { attestKeyArguments }
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
            _ keyId: String,
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            lock.withLock { attestKeyArguments.append((keyId, clientDataHash)) }
            completionHandler(nil, NSError(domain: DCErrorDomain, code: DCError.serverUnavailable.rawValue))
        }
    }

    /// A `DCAppAttestService` that answers `attestKey` and `generateAssertion`
    /// from a script after a scripted delay, and records how many of each call
    /// reached it and the most calls it had outstanding at one moment.
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
        private var attestKeyCalls = 0
        private var generateAssertionCalls = 0
        private var arrivals: [Arrival] = []

        /// One call that reached this double: which method, and the
        /// `clientDataHash` it carried.
        struct Arrival: Hashable {
            let method: String
            let clientDataHash: Data
        }

        /// Every `attestKey` and `generateAssertion` call, in arrival order.
        var arrivalOrder: [Arrival] {
            lock.withLock { arrivals }
        }

        /// Most calls this double had outstanding at one moment.
        var peakConcurrency: Int {
            lock.withLock { peakOutstandingCalls }
        }

        /// How many `attestKey` calls reached this double.
        var attestKeyCallCount: Int {
            lock.withLock { attestKeyCalls }
        }

        /// How many `generateAssertion` calls reached this double.
        var generateAssertionCallCount: Int {
            lock.withLock { generateAssertionCalls }
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
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            lock.withLock {
                attestKeyCalls += 1
                arrivals.append(Arrival(method: "attestKey", clientDataHash: clientDataHash))
            }
            answer(from: \.attestScript, to: completionHandler)
        }

        override func generateAssertion(
            _: String,
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            lock.withLock {
                generateAssertionCalls += 1
                arrivals.append(Arrival(method: "generateAssertion", clientDataHash: clientDataHash))
            }
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
    /// `generateKey` with a value, every `attestKey` with
    /// `attestationResult` and every `generateAssertion` with
    /// `assertionResult`, and records the key ID and
    /// `clientDataHash` of every `attestKey` and `generateAssertion` call in
    /// arrival order, so a test checks the exact bytes the adapter hands
    /// Apple. With `holdsFirstAssertion`, it answers its first
    /// `generateAssertion` only when a case calls `releaseHeldAssertion()`,
    /// with `holdsFirstKeyGeneration` its first `generateKey` only when a case
    /// calls `releaseHeldKeyGeneration()`, and with `holdsFirstAttestation`
    /// its first `attestKey` only when a case calls
    /// `releaseHeldAttestation()`, so a case keeps one App Attest call
    /// outstanding for as long as it needs.
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
        private var heldKeyGeneration: ((String?, Error?) -> Void)?
        private var heldAttestation: ((Data?, Error?) -> Void)?
        private let holdsFirstAssertion: Bool
        private let holdsFirstKeyGeneration: Bool
        private let holdsFirstAttestation: Bool
        private let attestationResult: Result<Data, Error>
        private let assertionResult: Result<Data, Error>

        init(
            holdsFirstAssertion: Bool = false,
            holdsFirstKeyGeneration: Bool = false,
            holdsFirstAttestation: Bool = false,
            attestationResult: Result<Data, Error> = .success(scriptedAttestation),
            assertionResult: Result<Data, Error> = .success(scriptedAssertion)
        ) {
            self.holdsFirstAssertion = holdsFirstAssertion
            self.holdsFirstKeyGeneration = holdsFirstKeyGeneration
            self.holdsFirstAttestation = holdsFirstAttestation
            self.attestationResult = attestationResult
            self.assertionResult = assertionResult
            super.init()
        }

        /// Whether the first `attestKey` is waiting for
        /// `releaseHeldAttestation()`.
        var isHoldingAttestation: Bool {
            lock.withLock { heldAttestation != nil }
        }

        /// Answer the held first `attestKey` with this double's attestation
        /// result, on the calling thread.
        func releaseHeldAttestation() {
            let handler: ((Data?, Error?) -> Void)? = lock.withLock {
                defer { heldAttestation = nil }
                return heldAttestation
            }
            if let handler {
                deliver(attestationResult, to: handler)
            }
        }

        /// Whether the first `generateKey` is waiting for
        /// `releaseHeldKeyGeneration()`.
        var isHoldingKeyGeneration: Bool {
            lock.withLock { heldKeyGeneration != nil }
        }

        /// Answer the held first `generateKey` with `generatedKeyId(1)`.
        func releaseHeldKeyGeneration() {
            let handler: ((String?, Error?) -> Void)? = lock.withLock {
                defer { heldKeyGeneration = nil }
                return heldKeyGeneration
            }
            handler?(Self.generatedKeyId(1), nil)
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
                if holdsFirstKeyGeneration, keysGenerated == 1 {
                    heldKeyGeneration = completionHandler
                }
                return keysGenerated
            }
            if holdsFirstKeyGeneration, ordinal == 1 {
                return
            }
            completionHandler(Self.generatedKeyId(ordinal), nil)
        }

        override func attestKey(
            _ keyId: String,
            clientDataHash: Data,
            completionHandler: @escaping (Data?, Error?) -> Void
        ) {
            let hold: Bool = lock.withLock {
                attestCalls.append(Call(keyId: keyId, clientDataHash: clientDataHash))
                if holdsFirstAttestation, attestCalls.count == 1 {
                    heldAttestation = completionHandler
                    return true
                }
                return false
            }
            if hold {
                return
            }
            deliver(attestationResult, to: completionHandler)
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
    ///
    /// A case can install `onNextAccess`, which runs once, on the next
    /// `string(forKey:)` or `set(_:forKey:)`, before that access completes.
    private final class InMemoryUserDefaults: UserDefaults {
        private let lock = NSLock()
        private var storage: [String: String] = [:]
        private var nextAccessHook: (() -> Void)?

        /// Run `hook` once, on the next read or write of any key.
        func onNextAccess(_ hook: @escaping () -> Void) {
            lock.withLock { nextAccessHook = hook }
        }

        private func runAccessHook() {
            let hook: (() -> Void)? = lock.withLock {
                defer { nextAccessHook = nil }
                return nextAccessHook
            }
            hook?()
        }

        override func string(forKey defaultName: String) -> String? {
            runAccessHook()
            return lock.withLock { storage[defaultName] }
        }

        override func set(_ value: Any?, forKey defaultName: String) {
            runAccessHook()
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
    /// when it is not `nil`, and recorded as attested when `attested` is true.
    private func makeAdapter(
        _ service: ScriptedAppAttestService,
        storedKeyId: String? = nil,
        attested: Bool = false
    ) -> AttestationHarness {
        let defaults = InMemoryUserDefaults()
        if let storedKeyId {
            defaults.set(storedKeyId, forKey: keyIdDefaultsKey)
            if attested {
                defaults.set(storedKeyId, forKey: attestedKeyIdDefaultsKey)
            }
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

    /// Poll `adapter`'s serializer until `count` callers wait in its queue, for
    /// at most ten seconds, and report whether they did.
    private func waitForWaitingCalls(_ count: Int, in adapter: AppleDeviceAttestation) async -> Bool {
        for _ in 0 ..< 10000 {
            if await adapter.waitingAppAttestCallCount() == count {
                return true
            }
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
        return await adapter.waitingAppAttestCallCount() == count
    }

    /// Return `task`'s value, or a "hung" marker when it has none after ten
    /// seconds. The bound makes a case whose caller never returns fail on its
    /// `#expect` instead of hanging the suite. Neither racer is a child task,
    /// so a hung `task` does not keep this function waiting.
    private func valueWithin(_ task: Task<String, Never>) async -> String {
        let (results, sink) = AsyncStream.makeStream(of: String.self)
        Task { sink.yield(await task.value) }
        let timer = Task {
            try? await Task.sleep(nanoseconds: 10_000_000_000)
            sink.yield("hung: no result within 10 seconds")
        }
        var first = "no result"
        for await result in results {
            first = result
            break
        }
        sink.finish()
        timer.cancel()
        return first
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
                .serviceError("m"), .unsupported("m"), .keyNotFound, .keyAlreadyAttested("m"), .keyNotAttested("m"),
                .keyRejected("m"), .serverUnavailable("m"), .internalError("m"), .invalidClientDataHash("m"),
                .timedOut("m")
            ]
            let codes = cases.compactMap { error -> String? in
                guard case let .Identity(_, code) = error.scpError else { return nil }
                return code
            }
            let expected = ["9001", "9019", "9020", "9021", "9022", "9023", "9024", "9025", "9026", "9027"]
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
                // `classify` reads only `attestKey` and `generateAssertion`
                // errors, so these `generateKey` answers give `serviceError`.
                FailureScript("generateKey serverUnavailable", ScriptedAppAttestService(supported: true, key: .serverUnavailable), "SCP-ATTEST-9001", storedKeyId: nil),
                FailureScript("generateKey invalidKey", ScriptedAppAttestService(supported: true, key: .invalidKey), "SCP-ATTEST-9001", storedKeyId: nil),
                FailureScript("attestKey error", ScriptedAppAttestService(supported: true, attestation: .failure), "SCP-ATTEST-9001", storedKeyId: scriptedKeyId),
                FailureScript("attestKey featureUnsupported", ScriptedAppAttestService(supported: true, attestation: .featureUnsupported), "SCP-ATTEST-9019", storedKeyId: scriptedKeyId),
                FailureScript("attestKey neither", ScriptedAppAttestService(supported: true, attestation: .neither), "SCP-ATTEST-9025", storedKeyId: scriptedKeyId),
                FailureScript("attestKey serverUnavailable", ScriptedAppAttestService(supported: true, attestation: .serverUnavailable), "SCP-ATTEST-9024", storedKeyId: scriptedKeyId)
                // `attestKey` answering `invalidKey` leads to the key probe,
                // whose answers `AppAttestKeyLifecycleTests` maps one by one.
            ]
            for script in scripts {
                let harness = makeAdapter(script.service)
                await expectCode(script.code, from: "attest (\(script.label))") { () async throws(ScpError) -> Data in
                    try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
                }
                #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == script.storedKeyId, "\(script.label)")
                #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == nil, "\(script.label)")
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
                FailureScript("generateAssertion neither", ScriptedAppAttestService(supported: true, assertion: .neither), "SCP-ATTEST-9025", storedKeyId: scriptedKeyId),
                FailureScript("generateAssertion serverUnavailable", ScriptedAppAttestService(supported: true, assertion: .serverUnavailable), "SCP-ATTEST-9024", storedKeyId: scriptedKeyId),
                FailureScript("generateAssertion invalidKey, no record", ScriptedAppAttestService(supported: true, assertion: .invalidKey), "SCP-ATTEST-9022", storedKeyId: scriptedKeyId)
            ]
            for script in scripts {
                let harness = makeAdapter(script.service, storedKeyId: script.storedKeyId)
                await expectCode(script.code, from: "assertRequest (\(script.label))") { () async throws(ScpError) -> Data in
                    try await harness.adapter.assertRequest(requestHash: requestHash)
                }
                // None of these answers names a rejected key, so each keeps it.
                #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == script.storedKeyId, "\(script.label)")
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

            let first = try await adapter.attest(challenge: challenge, deviceId: Data([0xFF, 0xEE]))
            let second = try await adapter.attest(challenge: challenge, deviceId: Data([0x01]))

            #expect(first == scriptedAttestation)
            #expect(second == scriptedAttestation)
            // Apple attests one key once, so the second attest hands Apple the
            // replacement key the adapter generated, under the same challenge.
            #expect(service.attestations == [
                .init(keyId: RecordingAppAttestService.generatedKeyId(1), clientDataHash: challenge),
                .init(keyId: RecordingAppAttestService.generatedKeyId(2), clientDataHash: challenge)
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

    /// Cases that pin `AppleDeviceAttestation`'s call serializer: while every
    /// call ends with Apple's answer, App Attest sees one outstanding call at
    /// a time, in the order the serializer accepts them, across every adapter
    /// over one `UserDefaults` object; the `isSupported` and 32-byte checks
    /// run before a call is queued; and a timed-out or cancelled call frees
    /// the serializer while Apple may still hold it.
    struct AppAttestCallOrderingTests {
        @Test("App Attest sees one outstanding call at a time while Apple answers every call")
        func appAttestCallsNeverOverlap() async {
            // `peakConcurrency` counts calls this double had outstanding at
            // once. Six callers starting together drive it above one for an
            // adapter that hands every caller straight to App Attest. The call
            // counts and the arrival record prove the first attestation and
            // each of the six callers reached Apple exactly once, so a peak of
            // one cannot come from callers that failed before calling out or
            // from a serializer that dropped one call and repeated another.
            // The six callers start together, so the serializer's acceptance
            // order among them is not fixed; the first attestation, awaited
            // before they start, reaches Apple first.
            // Every `attestKey` answers with an error, so the generated key
            // never carries an attestation record and each `attest` below
            // hands Apple that key rather than generating a replacement.
            let service = OverlapDetectingAppAttestService(
                attestScript: [.init(result: .failure(NSError(domain: "AppleDeviceAttestationTests", code: 4)), delay: 0.05)],
                assertScript: [.init(result: .success(Data([0xB1])), delay: 0.05)]
            )
            let adapter = AppleDeviceAttestation(service: service, defaults: InMemoryUserDefaults())

            // One attestation first, so every call below finds a stored key
            // ID rather than throwing `keyNotFound` before it calls out.
            _ = try? await adapter.attestReportingAttestationError(challenge: challenge, deviceId: deviceId)

            // 0x10 upward, so no caller's hash equals `challenge`.
            let callerHashes = (0 ..< 3).map { Data(repeating: UInt8(0x10 + $0), count: 32) }
            await withTaskGroup(of: Void.self) { group in
                for hash in callerHashes {
                    group.addTask {
                        _ = try? await adapter.attestReportingAttestationError(challenge: hash, deviceId: deviceId)
                    }
                    group.addTask {
                        _ = try? await adapter.assertRequestReportingAttestationError(requestHash: hash)
                    }
                }
            }

            #expect(
                service.peakConcurrency == 1,
                "App Attest saw \(service.peakConcurrency) outstanding calls at once"
            )
            #expect(
                service.attestKeyCallCount == 4,
                "attestKey reached Apple \(service.attestKeyCallCount) times, expected 4"
            )
            #expect(
                service.generateAssertionCallCount == 3,
                "generateAssertion reached Apple \(service.generateAssertionCallCount) times, expected 3"
            )
            typealias Arrival = OverlapDetectingAppAttestService.Arrival
            let arrivals = service.arrivalOrder
            #expect(arrivals.first == Arrival(method: "attestKey", clientDataHash: challenge))
            let callerArrivals = callerHashes.flatMap { hash in
                [Arrival(method: "attestKey", clientDataHash: hash), Arrival(method: "generateAssertion", clientDataHash: hash)]
            }
            #expect(arrivals.count == 7)
            #expect(Set(arrivals.dropFirst()) == Set(callerArrivals))
        }

        @Test("a call queued behind a running call reaches Apple only after Apple answers that call, even with an error")
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
            #expect(await valueWithin(first) == "SCP-ATTEST-9001")
            #expect(await valueWithin(second) == "SCP-ATTEST-9001")
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
            #expect(await valueWithin(held) == "returned bytes")
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
            // another. Each caller must reach `attestKey` once with the one
            // generated key ID and get Apple's `serverUnavailable` back as
            // `AttestationError.serverUnavailable`, which keeps the key, so one
            // generated key cannot come from seven callers that failed before
            // they called Apple.
            let challenges = (0 ..< 8).map { Data(repeating: UInt8($0), count: 32) }
            for round in 0 ..< 50 {
                let defaults = InMemoryUserDefaults()
                let service = CountingAppAttestService()
                let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

                let serverErrors = await withTaskGroup(of: Bool.self) { group in
                    for challenge in challenges {
                        group.addTask {
                            do throws(AttestationError) {
                                _ = try await adapter.attestReportingAttestationError(challenge: challenge, deviceId: deviceId)
                                return false
                            } catch {
                                guard case .serverUnavailable = error else { return false }
                                return true
                            }
                        }
                    }
                    return await group.reduce(0) { $0 + ($1 ? 1 : 0) }
                }

                let calls = service.attestKeyCalls
                #expect(serverErrors == 8, "round \(round): \(serverErrors) of 8 callers got Apple's error")
                #expect(calls.count == 8, "round \(round): attestKey reached Apple \(calls.count) times")
                #expect(calls.allSatisfy { $0.keyId == CountingAppAttestService.keyId })
                #expect(Set(calls.map(\.clientDataHash)) == Set(challenges))

                #expect(
                    service.keyGenerationCount == 1,
                    "round \(round) generated \(service.keyGenerationCount) App Attest keys"
                )
                #expect(defaults.string(forKey: keyIdDefaultsKey) == CountingAppAttestService.keyId)
            }
        }

        @Test("the production time limit on one App Attest call is 25 seconds, and an injected limit replaces it")
        func productionCallTimeLimitIsTwentyFiveSeconds() {
            // Alec's ruling of 2026-09-29 sets the bound at 25 seconds, below
            // the runtime's 30-second actor HANDLER_TIMEOUT. Any other value
            // turns this case red.
            #expect(AppleDeviceAttestation.appAttestCallTimeLimit == .seconds(25))
            #expect(AppleDeviceAttestation().callTimeLimit == .seconds(25))
            let service = RecordingAppAttestService()
            #expect(AppleDeviceAttestation(service: service, defaults: InMemoryUserDefaults()).callTimeLimit == .seconds(25))
            // An injected limit is the one the adapter holds, so the cases
            // below that inject a shorter limit run under it.
            let injected = AppleDeviceAttestation(
                service: service,
                defaults: InMemoryUserDefaults(),
                callTimeLimit: .milliseconds(300)
            )
            #expect(injected.callTimeLimit == .milliseconds(300))
            #expect(injected.callTimeLimit != AppleDeviceAttestation.appAttestCallTimeLimit)
        }

        @Test("a call Apple does not answer within the time limit throws SCP-ATTEST-9027, and the next queued call runs")
        func hungCallTimesOutAndNextCallRuns() async {
            let service = RecordingAppAttestService(holdsFirstAssertion: true)
            let defaults = InMemoryUserDefaults()
            defaults.set(RecordingAppAttestService.generatedKeyId(1), forKey: keyIdDefaultsKey)
            // One second gives the second caller time to join the queue before
            // the first call's limit expires, so the case exercises the
            // hand-off from a timed-out call to a queued one.
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults, callTimeLimit: .seconds(1))
            let secondHash = Data(repeating: 0xCD, count: 32)

            let first = Task { await code(of: { () async throws(ScpError) -> Data in
                try await adapter.assertRequest(requestHash: requestHash)
            }) }
            #expect(await waitUntil { service.isHoldingAssertion }, "the first assertRequest never reached Apple")
            let second = Task { await code(of: { () async throws(ScpError) -> Data in
                try await adapter.assertRequest(requestHash: secondHash)
            }) }
            // The queue holds a caller only while another call runs, so a
            // count of one here proves the second call queued behind the
            // first before the first timed out.
            #expect(await waitForWaitingCalls(1, in: adapter), "the second assertRequest never joined the queue")
            #expect(service.assertions.count == 1, "the queued assertRequest reached Apple before the first call ended")

            #expect(await valueWithin(first) == "SCP-ATTEST-9027")
            #expect(await valueWithin(second) == "returned bytes")
            #expect(service.isHoldingAssertion, "the queued call waited for Apple to answer the timed-out call")
            #expect(service.assertions.map(\.clientDataHash) == [requestHash, secondHash])

            // Apple answers the timed-out call now. The answer reaches no
            // caller: a second resume of the first caller's continuation
            // would crash the suite.
            service.releaseHeldAssertion()
            // A call Apple answers within the time limit returns its bytes.
            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await adapter.assertRequest(requestHash: requestHash)
            }) == "returned bytes")
            #expect(service.assertions.map(\.clientDataHash) == [requestHash, secondHash, requestHash])
        }

        @Test("a generateKey answer that arrives after the time limit stores no key ID and reaches no attestKey")
        func lateAnswerWritesNothing() async {
            let service = RecordingAppAttestService(holdsFirstKeyGeneration: true)
            let defaults = InMemoryUserDefaults()
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults, callTimeLimit: .milliseconds(300))

            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await adapter.attest(challenge: challenge, deviceId: deviceId)
            }) == "SCP-ATTEST-9027")
            #expect(service.isHoldingKeyGeneration)

            // The held completion handler runs on this thread, so every write
            // it makes has happened when this call returns.
            service.releaseHeldKeyGeneration()
            #expect(defaults.string(forKey: keyIdDefaultsKey) == nil, "a late generateKey answer stored its key ID")
            #expect(service.attestations.isEmpty, "a late generateKey answer reached attestKey")

            // The next attest generates its own key, stores it and attests it.
            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await adapter.attest(challenge: challenge, deviceId: deviceId)
            }) == "returned bytes")
            #expect(defaults.string(forKey: keyIdDefaultsKey) == RecordingAppAttestService.generatedKeyId(2))
            #expect(service.attestations == [
                .init(keyId: RecordingAppAttestService.generatedKeyId(2), clientDataHash: challenge)
            ])
        }

        @Test("a caller cancelled while queued leaves the queue and never reaches Apple")
        func cancelledQueuedCallerNeverReachesApple() async {
            let service = RecordingAppAttestService(holdsFirstAssertion: true)
            let defaults = InMemoryUserDefaults()
            defaults.set(RecordingAppAttestService.generatedKeyId(1), forKey: keyIdDefaultsKey)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

            let held = Task { await code(of: { () async throws(ScpError) -> Data in
                try await adapter.assertRequest(requestHash: requestHash)
            }) }
            #expect(await waitUntil { service.isHoldingAssertion }, "the held assertRequest never reached Apple")
            let queued = Task { await code(of: { () async throws(ScpError) -> Data in
                try await adapter.assertRequest(requestHash: Data(repeating: 0xCD, count: 32))
            }) }
            #expect(await waitForWaitingCalls(1, in: adapter), "the second assertRequest never joined the queue")

            queued.cancel()
            #expect(await valueWithin(queued) == "SCP-ATTEST-9001")
            #expect(await adapter.waitingAppAttestCallCount() == 0)
            #expect(service.isHoldingAssertion, "the cancelled caller waited for the held assertion")

            service.releaseHeldAssertion()
            #expect(await valueWithin(held) == "returned bytes")
            #expect(service.assertions.map(\.clientDataHash) == [requestHash])
        }

        @Test("a caller cancelled while Apple holds its call frees the queue for the next call")
        func cancelledWaitingCallerFreesQueue() async {
            let service = RecordingAppAttestService(holdsFirstAssertion: true)
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
            #expect(await waitForWaitingCalls(1, in: adapter), "the second assertRequest never joined the queue")

            first.cancel()
            #expect(await valueWithin(first) == "SCP-ATTEST-9001")
            #expect(await valueWithin(second) == "returned bytes")
            #expect(service.isHoldingAssertion, "the second call waited for Apple to answer the cancelled call")
            #expect(service.assertions.map(\.clientDataHash) == [requestHash, secondHash])

            // Apple's answer to the cancelled call reaches no caller.
            service.releaseHeldAssertion()
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

    /// Cases that pin when a serialized App Attest call ends, so a call never
    /// starts an App Attest method after it ended:
    ///
    /// - An end that arrives while the adapter stores a generated key ID
    ///   takes effect only after the `attestKey` that step leads to started.
    ///   Removing `issuing == 0` from `AppAttestCall.State.takeDelivery()`,
    ///   or storing the key ID and calling `attestKey` outside `call.issue`,
    ///   turns `endBetweenKeyStoreAndAttestKeyComesAfterAttestKey` red.
    /// - An end that arrives while the adapter reads the stored key ID takes
    ///   effect at once, and the call then hands App Attest no method.
    ///   Calling `generateKey`, `attestKey` or `generateAssertion` outside
    ///   `call.issue` after the read, or dropping the
    ///   `state.isOpen` guard of `issue`, turns
    ///   `endDuringKeyReadStartsNoMethod` red.
    /// - A caller whose task is cancelled before its call starts, whether
    ///   before it reached the serializer or after the serializer admitted
    ///   it, takes one path through `AppAttestCall.run`: the cancellation
    ///   handler ends the call before `run` takes its lock, and `run` then
    ///   neither calls `start` nor reads the key ID. Calling `start` whatever
    ///   `open` says turns `callerCancelledBeforeItsCallStartsNeverReachesApple`
    ///   red.
    struct AppAttestCallEndTests {
        @Test("a cancellation during the key-ID read ends the call before it hands App Attest any method")
        func endDuringKeyReadStartsNoMethod() async {
            let service = RecordingAppAttestService()
            let defaults = InMemoryUserDefaults()
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)
            let attest: @Sendable () async throws(ScpError) -> Data = {
                try await adapter.attest(challenge: challenge, deviceId: deviceId)
            }
            let assertion: @Sendable () async throws(ScpError) -> Data = {
                try await adapter.assertRequest(requestHash: requestHash)
            }
            /// The hook runs inside the key-ID read, on the caller's own task,
            /// and cancels that task there.
            func cancelDuringRead() {
                defaults.onNextAccess {
                    withUnsafeCurrentTask { task in
                        if let task {
                            task.cancel()
                        }
                    }
                }
            }

            // No key ID stored: the read comes before `generateKey`.
            cancelDuringRead()
            #expect(await valueWithin(Task { await code(of: attest) }) == "SCP-ATTEST-9001")
            #expect(service.generatedKeyCount == 0, "generateKey started after the call ended")
            #expect(defaults.string(forKey: keyIdDefaultsKey) == nil)

            // An uncancelled attest generates, stores and attests one key.
            #expect(await valueWithin(Task { await code(of: attest) }) == "returned bytes")
            #expect(service.generatedKeyCount == 1)
            #expect(service.attestations.count == 1)

            // A key ID stored with no attestation record, so an uncancelled
            // attest would reach `attestKey`: the read comes before it.
            defaults.removeObject(forKey: attestedKeyIdDefaultsKey)
            cancelDuringRead()
            #expect(await valueWithin(Task { await code(of: attest) }) == "SCP-ATTEST-9001")
            #expect(service.attestations.count == 1, "attestKey started after the call ended")

            // A key ID stored: the read comes before `generateAssertion`.
            cancelDuringRead()
            #expect(await valueWithin(Task { await code(of: assertion) }) == "SCP-ATTEST-9001")
            #expect(service.assertions.isEmpty, "generateAssertion started after the call ended")

            // An uncancelled assertRequest reaches Apple once.
            #expect(await valueWithin(Task { await code(of: assertion) }) == "returned bytes")
            #expect(service.assertions == [
                .init(keyId: RecordingAppAttestService.generatedKeyId(1), clientDataHash: requestHash)
            ])
            #expect(service.generatedKeyCount == 1)
            #expect(service.attestations.count == 1)
        }

        @Test("a caller cancelled before its call starts reads no key ID, never reaches Apple, and frees the serializer")
        func callerCancelledBeforeItsCallStartsNeverReachesApple() async {
            let service = RecordingAppAttestService()
            let defaults = InMemoryUserDefaults()
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)
            let attest: @Sendable () async throws(ScpError) -> Data = {
                try await adapter.attest(challenge: challenge, deviceId: deviceId)
            }
            let assertion: @Sendable () async throws(ScpError) -> Data = {
                try await adapter.assertRequest(requestHash: requestHash)
            }
            let keyRead = OSAllocatedUnfairLock(initialState: false)
            func noteNextKeyRead() {
                keyRead.withLock { $0 = false }
                defaults.onNextAccess { keyRead.withLock { $0 = true } }
            }
            func cancelledCaller(_ call: @escaping @Sendable () async throws(ScpError) -> Data) -> Task<String, Never> {
                Task {
                    withUnsafeCurrentTask { task in
                        if let task {
                            task.cancel()
                        }
                    }
                    return await code(of: call)
                }
            }

            noteNextKeyRead()
            #expect(await valueWithin(cancelledCaller(attest)) == "SCP-ATTEST-9001")
            #expect(!keyRead.withLock { $0 }, "the cancelled attest read the stored key ID")
            #expect(service.generatedKeyCount == 0)
            #expect(service.attestations.isEmpty)

            // The serializer is free: an uncancelled attest runs at once,
            // reads the key ID, and stores the key ID the next calls read.
            #expect(await valueWithin(Task { await code(of: attest) }) == "returned bytes")
            #expect(keyRead.withLock { $0 }, "the uncancelled attest never read the stored key ID")
            #expect(service.generatedKeyCount == 1)
            #expect(service.attestations.count == 1)

            noteNextKeyRead()
            #expect(await valueWithin(cancelledCaller(assertion)) == "SCP-ATTEST-9001")
            #expect(!keyRead.withLock { $0 }, "the cancelled assertRequest read the stored key ID")
            #expect(service.assertions.isEmpty)

            #expect(await valueWithin(Task { await code(of: assertion) }) == "returned bytes")
            #expect(keyRead.withLock { $0 }, "the uncancelled assertRequest never read the stored key ID")
            #expect(service.assertions.map(\.clientDataHash) == [requestHash])
        }

        @Test("a cancellation between the generated key's store and attestKey ends the call only after attestKey started")
        func endBetweenKeyStoreAndAttestKeyComesAfterAttestKey() async {
            let service = RecordingAppAttestService(holdsFirstKeyGeneration: true)
            let defaults = InMemoryUserDefaults()
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)
            let callerReturned = DispatchSemaphore(value: 0)
            let caller = Task { () -> (code: String, attestKeyCalls: Int) in
                let outcome = await code(of: { () async throws(ScpError) -> Data in
                    try await adapter.attest(challenge: challenge, deviceId: deviceId)
                })
                let attestKeyCalls = service.attestations.count
                callerReturned.signal()
                return (outcome, attestKeyCalls)
            }
            #expect(await waitUntil { service.isHoldingKeyGeneration }, "the attest never reached generateKey")

            // Cancel the caller while the adapter stores the generated key
            // ID, the step before its `attestKey` call, and give the caller
            // 300 milliseconds to return. A caller that returns here was
            // resumed by a call that went on to start `attestKey`.
            defaults.onNextAccess {
                caller.cancel()
                _ = callerReturned.wait(timeout: .now() + .milliseconds(300))
            }
            service.releaseHeldKeyGeneration()

            let result = await caller.value
            #expect(result.code == "SCP-ATTEST-9001")
            #expect(result.attestKeyCalls == 1, "the caller returned before its call's attestKey started")
            #expect(service.attestations == [
                .init(keyId: RecordingAppAttestService.generatedKeyId(1), clientDataHash: challenge)
            ])
            #expect(defaults.string(forKey: keyIdDefaultsKey) == RecordingAppAttestService.generatedKeyId(1))
        }
    }

    // MARK: - App Attest key lifecycle

    /// The error `generateAssertion` or `attestKey` answers with for
    /// `DCError.invalidKey`.
    private let invalidKeyError = NSError(domain: DCErrorDomain, code: DCError.invalidKey.rawValue)

    /// The key-probe input `K` of `09-security-model.md` §9.3.1, written out
    /// here instead of read from the adapter, so a change to the bytes the
    /// adapter's key probe signs fails a case.
    private let keyProbeInput = Data(SHA256.hash(data: Data("SCP-APP-ATTEST-KEY-PROBE-V1".utf8)))

    /// `DCError.h` lists three conditions behind `DCErrorInvalidKey`: calling
    /// `attestKey:clientDataHash:completionHandler:` for a key already
    /// attested, calling `generateAssertion:clientDataHash:completionHandler:`
    /// with an unattested key, and an App Attest service rejecting a key. Only
    /// the third, in which Apple's service rejects the key, discards a key ID.
    /// Each case drives one condition, or `DCError.serverUnavailable`,
    /// and pins what happens to the stored key ID and the attestation record,
    /// so collapsing the conditions into one fails a case.
    struct AppAttestKeyLifecycleTests {
        @Test("assertRequest throws SCP-ATTEST-9024 and keeps an attested key when generateAssertion answers serverUnavailable")
        func assertRequestKeepsKeyOnServerUnavailable() async {
            let service = ScriptedAppAttestService(supported: true, assertion: .serverUnavailable)
            let harness = makeAdapter(service, storedKeyId: scriptedKeyId, attested: true)

            await expectCode("SCP-ATTEST-9024", from: "assertRequest") { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == scriptedKeyId)
        }

        @Test("assertRequest throws SCP-ATTEST-9022 and keeps a key that carries no attestation record")
        func assertRequestKeepsUnattestedKey() async {
            let service = ScriptedAppAttestService(supported: true, assertion: .invalidKey)
            let harness = makeAdapter(service, storedKeyId: scriptedKeyId)

            await expectCode("SCP-ATTEST-9022", from: "assertRequest") { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }
            // Apple answers `invalidKey` for an assertion over an unattested
            // key, and that key is alive and waits for its attestation.
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == nil)
        }

        @Test("assertRequest throws SCP-ATTEST-9023 and discards an attested key Apple's service rejected")
        func assertRequestDiscardsRejectedKey() async {
            let service = ScriptedAppAttestService(supported: true, assertion: .invalidKey)
            let harness = makeAdapter(service, storedKeyId: scriptedKeyId, attested: true)

            await expectCode("SCP-ATTEST-9023", from: "assertRequest") { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }
            // Apple attested this key, so `invalidKey` from
            // `generateAssertion` names a rejected key.
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == nil)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == nil)

            // The next attest generates a new key instead of reusing the
            // rejected one.
            await expectCode("SCP-ATTEST-9020", from: "assertRequest after the discard") { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }
            #expect(service.keyGenerationCount == 0)
            _ = try? await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            #expect(service.keyGenerationCount == 1)
        }

        @Test("attest throws SCP-ATTEST-9024 and keeps its key when attestKey answers serverUnavailable")
        func attestKeepsKeyOnServerUnavailable() async {
            let service = ScriptedAppAttestService(supported: true, attestation: .serverUnavailable)
            let harness = makeAdapter(service, storedKeyId: scriptedKeyId)

            await expectCode("SCP-ATTEST-9024", from: "attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }
            // `DCError.h` says to retry that attestation later with the same
            // key, because retrying with the same inputs preserves the
            // device's risk metric.
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == nil)
            #expect(service.keyGenerationCount == 0)
        }

        @Test("an assertion after a failed attestation keeps the key, and the retried attestation succeeds with it")
        func assertionAfterFailedAttestationKeepsKey() async {
            let service = ScriptedAppAttestService(
                supported: true,
                attestation: .serverUnavailable,
                thenAttestation: .value(scriptedAttestation),
                assertion: .invalidKey
            )
            let harness = makeAdapter(service)

            // The first attestation generates a key and then fails to reach
            // Apple, so that key stays stored and unattested.
            await expectCode("SCP-ATTEST-9024", from: "first attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)

            // An assertion before the retry hits an unattested key. Discarding
            // that key would throw away what the retry needs.
            await expectCode("SCP-ATTEST-9022", from: "assertRequest") { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)

            // Retrying the attestation with the same key succeeds and records it.
            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }) == "returned bytes")
            #expect(service.keyGenerationCount == 1)
            #expect(service.attestKeyCount == 2)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == scriptedKeyId)
        }

        @Test("attest throws SCP-ATTEST-9025 and records no attestation when attestKey answers with nothing")
        func attestRejectsEmptyAttestation() async {
            let service = ScriptedAppAttestService(supported: true, attestation: .neither)
            let harness = makeAdapter(service)

            await expectCode("SCP-ATTEST-9025", from: "attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == nil)
        }

        @Test("a freshly generated key carries no attestation record left by an earlier key")
        func generatedKeyCarriesNoStaleAttestation() async {
            let service = ScriptedAppAttestService(supported: true, attestation: .serverUnavailable, assertion: .invalidKey)
            let harness = makeAdapter(service)
            // A record naming the very key ID `generateKey` is about to hand
            // back, which a generated key must not inherit. Inheriting it would
            // classify the assertion below, over an unattested key, as a
            // rejected attested key and discard a key a retry needs.
            harness.defaults.set(scriptedKeyId, forKey: attestedKeyIdDefaultsKey)

            await expectCode("SCP-ATTEST-9024", from: "attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == nil)

            await expectCode("SCP-ATTEST-9022", from: "assertRequest") { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
        }

        @Test("a queued assertion reads the key ID after its predecessor discarded it")
        func queuedAssertionReadsKeyIdAfterPredecessor() async {
            let service = RecordingAppAttestService(holdsFirstAssertion: true, assertionResult: .failure(invalidKeyError))
            let defaults = InMemoryUserDefaults()
            let keyId = RecordingAppAttestService.generatedKeyId(1)
            defaults.set(keyId, forKey: keyIdDefaultsKey)
            defaults.set(keyId, forKey: attestedKeyIdDefaultsKey)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)

            // The first assertion reaches Apple and waits there; Apple then
            // rejects that attested key, so the adapter discards its key ID.
            let first = Task { await code(of: { () async throws(ScpError) -> Data in
                try await adapter.assertRequest(requestHash: requestHash)
            }) }
            #expect(await waitUntil { service.isHoldingAssertion }, "the first assertRequest never reached Apple")
            // The second assertion queues while the first is outstanding. An
            // adapter that read the key ID before queueing would hand Apple
            // the discarded key ID and throw `keyNotAttested`.
            let second = Task { await code(of: { () async throws(ScpError) -> Data in
                try await adapter.assertRequest(requestHash: Data(repeating: 0xCD, count: 32))
            }) }
            #expect(await waitForWaitingCalls(1, in: adapter), "the second assertRequest never joined the queue")
            service.releaseHeldAssertion()

            #expect(await valueWithin(first) == "SCP-ATTEST-9023")
            #expect(await valueWithin(second) == "SCP-ATTEST-9020")
            #expect(service.assertions.map(\.clientDataHash) == [requestHash])
            #expect(defaults.string(forKey: keyIdDefaultsKey) == nil)
            #expect(defaults.string(forKey: attestedKeyIdDefaultsKey) == nil)
        }

        @Test("an attestKey answer that arrives after the time limit writes no attestation record")
        func lateAttestationWritesNoRecord() async {
            let service = RecordingAppAttestService(holdsFirstAttestation: true)
            let defaults = InMemoryUserDefaults()
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults, callTimeLimit: .milliseconds(300))

            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await adapter.attest(challenge: challenge, deviceId: deviceId)
            }) == "SCP-ATTEST-9027")
            #expect(service.isHoldingAttestation)

            // The held completion handler runs on this thread, so every write
            // it makes has happened when this call returns.
            service.releaseHeldAttestation()
            #expect(defaults.string(forKey: attestedKeyIdDefaultsKey) == nil, "a late attestKey answer wrote the record")
            // The key ID `generateKey` stored before the time limit stays.
            #expect(defaults.string(forKey: keyIdDefaultsKey) == RecordingAppAttestService.generatedKeyId(1))
            #expect(service.generatedKeyCount == 1)
            #expect(service.attestations.count == 1)
        }

        @Test("a generateAssertion invalidKey answer that arrives after the time limit discards no key ID")
        func lateRejectionDiscardsNothing() async {
            let service = RecordingAppAttestService(holdsFirstAssertion: true, assertionResult: .failure(invalidKeyError))
            let defaults = InMemoryUserDefaults()
            let keyId = RecordingAppAttestService.generatedKeyId(1)
            defaults.set(keyId, forKey: keyIdDefaultsKey)
            defaults.set(keyId, forKey: attestedKeyIdDefaultsKey)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults, callTimeLimit: .milliseconds(300))

            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await adapter.assertRequest(requestHash: requestHash)
            }) == "SCP-ATTEST-9027")
            #expect(service.isHoldingAssertion)

            service.releaseHeldAssertion()
            #expect(defaults.string(forKey: keyIdDefaultsKey) == keyId, "a late rejection discarded the key ID")
            #expect(defaults.string(forKey: attestedKeyIdDefaultsKey) == keyId, "a late rejection discarded the record")
        }

        // MARK: Key probe

        @Test("attest throws SCP-ATTEST-9021, keeps and records the key, when the key probe's assertion succeeds")
        func attestProbeFindsAlreadyAttestedKey() async {
            // Apple attested the stored key, but this adapter holds no record
            // of it, so `attestKey` answers `invalidKey` and an assertion with
            // that key succeeds. Discarding the key would strand a live
            // Secure Enclave key.
            let replacementKeyId = "replacement-app-attest-key"
            let service = ScriptedAppAttestService(
                supported: true,
                key: .value(replacementKeyId),
                attestation: .invalidKey,
                thenAttestation: .value(scriptedAttestation)
            )
            let harness = makeAdapter(service, storedKeyId: scriptedKeyId)

            await expectCode("SCP-ATTEST-9021", from: "attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == scriptedKeyId)
            // The probe asks for one assertion with the stored key over `K`,
            // never over the attestation's challenge `D`.
            #expect(service.generateAssertionCount == 1)
            #expect(service.generateAssertionCall?.keyId == scriptedKeyId)
            #expect(service.generateAssertionCall?.clientDataHash == keyProbeInput)
            #expect(service.generateAssertionCall?.clientDataHash != challenge)

            // The record the probe wrote makes the next attest generate and
            // attest a replacement key rather than hand Apple the stored key.
            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: Data(repeating: 0x03, count: 32), deviceId: deviceId)
            }) == "returned bytes")
            #expect(service.keyGenerationCount == 1)
            #expect(service.attestedKeyIds == [scriptedKeyId, replacementKeyId])
            #expect(service.generateAssertionCount == 1)
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == replacementKeyId)
        }

        @Test("attest throws SCP-ATTEST-9023 and discards the key when attestKey and the key probe both answer invalidKey")
        func attestDiscardsRejectedKey() async {
            let service = ScriptedAppAttestService(supported: true, attestation: .invalidKey, assertion: .invalidKey)
            let harness = makeAdapter(service, storedKeyId: scriptedKeyId)

            await expectCode("SCP-ATTEST-9023", from: "attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == nil)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == nil)
            #expect(service.generateAssertionCall?.clientDataHash == keyProbeInput)

            // The next attest generates a new key.
            _ = try? await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            #expect(service.keyGenerationCount == 1)
        }

        @Test("attest maps each other key probe answer to its SCP-ATTEST code and keeps the key unrecorded")
        func attestProbeKeepsKeyOnEveryOtherAnswer() async {
            let scripts = [
                FailureScript("probe serverUnavailable", ScriptedAppAttestService(supported: true, attestation: .invalidKey, assertion: .serverUnavailable), "SCP-ATTEST-9024", storedKeyId: scriptedKeyId),
                FailureScript("probe featureUnsupported", ScriptedAppAttestService(supported: true, attestation: .invalidKey, assertion: .featureUnsupported), "SCP-ATTEST-9019", storedKeyId: scriptedKeyId),
                FailureScript("probe error", ScriptedAppAttestService(supported: true, attestation: .invalidKey, assertion: .failure), "SCP-ATTEST-9001", storedKeyId: scriptedKeyId),
                // Neither an assertion nor an error says nothing about the key.
                FailureScript("probe neither", ScriptedAppAttestService(supported: true, attestation: .invalidKey, assertion: .neither), "SCP-ATTEST-9025", storedKeyId: scriptedKeyId)
            ]
            for script in scripts {
                let harness = makeAdapter(script.service, storedKeyId: scriptedKeyId)
                await expectCode(script.code, from: "attest (\(script.label))") { () async throws(ScpError) -> Data in
                    try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
                }
                #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == script.storedKeyId, "\(script.label)")
                #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == nil, "\(script.label)")
                #expect(script.service.generateAssertionCall?.clientDataHash == keyProbeInput, "\(script.label)")
            }
        }

        @Test("attest throws SCP-ATTEST-9025 when the invalidKey probe's generateAssertion answers with nothing")
        func attestProbeReportsEmptyAssertionAsInternalError() async {
            // A generated key, so the probe also runs on a key this attest
            // stored itself.
            let service = ScriptedAppAttestService(supported: true, attestation: .invalidKey, assertion: .neither)
            let harness = makeAdapter(service)

            await expectCode("SCP-ATTEST-9025", from: "attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }
            // The probe learned nothing about the key, so the adapter keeps
            // it and records no attestation for it.
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == nil)
            #expect(service.generateAssertionCount == 1)
        }

        @Test("a key probe invalidKey answer that arrives after the time limit discards no key ID")
        func lateProbeRejectionDiscardsNothing() async {
            let service = RecordingAppAttestService(
                holdsFirstAssertion: true,
                attestationResult: .failure(invalidKeyError),
                assertionResult: .failure(invalidKeyError)
            )
            let defaults = InMemoryUserDefaults()
            let keyId = RecordingAppAttestService.generatedKeyId(1)
            defaults.set(keyId, forKey: keyIdDefaultsKey)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults, callTimeLimit: .milliseconds(300))

            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await adapter.attest(challenge: challenge, deviceId: deviceId)
            }) == "SCP-ATTEST-9027")
            #expect(service.isHoldingAssertion)
            #expect(service.assertions == [RecordingAppAttestService.Call(keyId: keyId, clientDataHash: keyProbeInput)])

            // The held completion handler runs on this thread, so every write
            // it makes has happened when this call returns.
            service.releaseHeldAssertion()
            #expect(defaults.string(forKey: keyIdDefaultsKey) == keyId, "a late probe answer discarded the key ID")
        }

        @Test("a key probe assertion that arrives after the time limit writes no attestation record")
        func lateProbeAssertionWritesNoRecord() async {
            let service = RecordingAppAttestService(
                holdsFirstAssertion: true,
                attestationResult: .failure(invalidKeyError)
            )
            let defaults = InMemoryUserDefaults()
            let keyId = RecordingAppAttestService.generatedKeyId(1)
            defaults.set(keyId, forKey: keyIdDefaultsKey)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults, callTimeLimit: .milliseconds(300))

            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await adapter.attest(challenge: challenge, deviceId: deviceId)
            }) == "SCP-ATTEST-9027")
            #expect(service.isHoldingAssertion)
            #expect(service.assertions == [RecordingAppAttestService.Call(keyId: keyId, clientDataHash: keyProbeInput)])

            // The held completion handler runs on this thread, so every write
            // it makes has happened when this call returns.
            service.releaseHeldAssertion()
            #expect(defaults.string(forKey: attestedKeyIdDefaultsKey) == nil, "a late probe assertion wrote the attestation record")
            #expect(defaults.string(forKey: keyIdDefaultsKey) == keyId)
        }

        @Test("an attestKey invalidKey answer that arrives after the time limit starts no key probe")
        func lateInvalidKeyStartsNoProbe() async {
            let service = RecordingAppAttestService(
                holdsFirstAttestation: true,
                attestationResult: .failure(invalidKeyError),
                assertionResult: .failure(invalidKeyError)
            )
            let defaults = InMemoryUserDefaults()
            let keyId = RecordingAppAttestService.generatedKeyId(1)
            defaults.set(keyId, forKey: keyIdDefaultsKey)
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults, callTimeLimit: .milliseconds(300))

            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await adapter.attest(challenge: challenge, deviceId: deviceId)
            }) == "SCP-ATTEST-9027")
            #expect(service.isHoldingAttestation)

            // The held completion handler runs on this thread, so any probe
            // it started has reached the double when this call returns.
            service.releaseHeldAttestation()
            #expect(service.assertions.isEmpty, "a late attestKey answer started a key probe")
            #expect(defaults.string(forKey: keyIdDefaultsKey) == keyId)
        }
    }

    // MARK: - Replacement key

    /// Cases that pin the replacement key: `attest` generates and attests one
    /// when the stored key carries an attestation record, including when that
    /// record lands while the `attest` waits in the queue, and a failed
    /// replacement attestation leaves the attested key in place.
    ///
    /// A key generated to replace an attested key is stored apart from it
    /// until Apple attests it, so `assertRequest` keeps naming the key an
    /// earlier published attestation names whatever the replacement's
    /// `attestKey` answers.
    struct AppAttestKeyReplacementTests {
        @Test("two attests in a row attest two keys, and an assertion reaches the second")
        func repeatedAttestReplacesKey() async {
            let secondKeyId = "second-app-attest-key"
            let secondAttestation = Data([0xC1, 0xC2])
            let service = ScriptedAppAttestService(
                supported: true,
                thenKey: .value(secondKeyId),
                thenAttestation: .value(secondAttestation)
            )
            let harness = makeAdapter(service)

            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }) == "returned bytes")
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == scriptedKeyId)

            // A second context needs its own attestation, and Apple attests one
            // key once, so this call must not hand Apple the attested key.
            let second = try? await harness.adapter.attest(challenge: Data(repeating: 0x03, count: 32), deviceId: deviceId)
            #expect(second == secondAttestation)
            #expect(service.keyGenerationCount == 2)
            #expect(service.attestedKeyIds == [scriptedKeyId, secondKeyId])
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == secondKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == secondKeyId)
            #expect(harness.defaults.string(forKey: replacementKeyIdDefaultsKey) == nil)

            // Assertions move to the key the latest attestation names.
            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }) == "returned bytes")
            #expect(service.assertedKeyIds == [secondKeyId])
        }

        @Test("attest generates and attests a replacement key when the stored key carries an attestation record")
        func attestReplacesAttestedKey() async {
            let service = ScriptedAppAttestService(supported: true)
            let harness = makeAdapter(service, storedKeyId: storedKeyId, attested: true)

            let attestation = try? await harness.adapter.attest(challenge: challenge, deviceId: deviceId)

            // §9.3.1 of the security model spec keeps one attestation per
            // context, and Apple attests one key once, so a second context
            // needs a second key.
            #expect(attestation == scriptedAttestation)
            #expect(service.keyGenerationCount == 1)
            #expect(service.attestedKeyIds == [scriptedKeyId])
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == scriptedKeyId)
            #expect(harness.defaults.string(forKey: replacementKeyIdDefaultsKey) == nil)
        }

        @Test("an attest queued behind an attest Apple holds attests a replacement key rather than the first key")
        func concurrentAttestReplacesAttestedKey() async {
            // A second caller that read the stored key before the first
            // caller recorded its attestation would hand Apple that key
            // again, which Apple attests once.
            let service = RecordingAppAttestService(holdsFirstAttestation: true)
            let defaults = InMemoryUserDefaults()
            let adapter = AppleDeviceAttestation(service: service, defaults: defaults)
            let secondChallenge = Data(repeating: 0x03, count: 32)

            let first = Task { await code(of: { () async throws(ScpError) -> Data in
                try await adapter.attest(challenge: challenge, deviceId: deviceId)
            }) }
            #expect(await waitUntil { service.isHoldingAttestation }, "the first attest never reached attestKey")
            let second = Task { await code(of: { () async throws(ScpError) -> Data in
                try await adapter.attest(challenge: secondChallenge, deviceId: deviceId)
            }) }
            #expect(await waitForWaitingCalls(1, in: adapter), "the second attest never joined the queue")

            service.releaseHeldAttestation()
            #expect(await valueWithin(first) == "returned bytes")
            #expect(await valueWithin(second) == "returned bytes")
            #expect(service.attestations == [
                .init(keyId: RecordingAppAttestService.generatedKeyId(1), clientDataHash: challenge),
                .init(keyId: RecordingAppAttestService.generatedKeyId(2), clientDataHash: secondChallenge)
            ])
            #expect(defaults.string(forKey: keyIdDefaultsKey) == RecordingAppAttestService.generatedKeyId(2))
            #expect(defaults.string(forKey: attestedKeyIdDefaultsKey) == RecordingAppAttestService.generatedKeyId(2))
        }

        @Test("two adapters over one defaults object never hand Apple one key twice")
        func adaptersSharingDefaultsAttestEachKeyOnce() async {
            // Both adapters read the stored, unattested key. Unless they share
            // one serializer, both hand Apple that key, which Apple attests
            // once.
            let service = RecordingAppAttestService(holdsFirstAttestation: true)
            let defaults = InMemoryUserDefaults()
            defaults.set(storedKeyId, forKey: keyIdDefaultsKey)
            let first = AppleDeviceAttestation(service: service, defaults: defaults)
            let second = AppleDeviceAttestation(service: service, defaults: defaults)

            let firstCall = Task { await code(of: { () async throws(ScpError) -> Data in
                try await first.attest(challenge: challenge, deviceId: deviceId)
            }) }
            #expect(await waitUntil { service.isHoldingAttestation }, "the first adapter's attest never reached attestKey")
            let secondCall = Task { await code(of: { () async throws(ScpError) -> Data in
                try await second.attest(challenge: challenge, deviceId: deviceId)
            }) }
            #expect(await waitForWaitingCalls(1, in: second), "the second adapter's attest never joined the shared queue")

            service.releaseHeldAttestation()
            #expect(await valueWithin(firstCall) == "returned bytes")
            #expect(await valueWithin(secondCall) == "returned bytes")
            let keyIds = service.attestations.map(\.keyId)
            #expect(keyIds == [storedKeyId, RecordingAppAttestService.generatedKeyId(1)])
            #expect(Set(keyIds).count == keyIds.count, "Apple was asked to attest one key twice")
        }

        @Test("a replacement attestation that cannot reach Apple leaves assertions on the attested key")
        func failedReplacementKeepsAttestedKey() async {
            let retriedAttestation = Data([0xA2])
            let service = ScriptedAppAttestService(
                supported: true,
                attestation: .serverUnavailable,
                thenAttestation: .value(retriedAttestation)
            )
            let harness = makeAdapter(service, storedKeyId: storedKeyId, attested: true)

            await expectCode("SCP-ATTEST-9024", from: "attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }

            // The attested key an earlier published attestation names stays the
            // key assertions use, and the replacement waits for its retry.
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == storedKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == storedKeyId)
            #expect(harness.defaults.string(forKey: replacementKeyIdDefaultsKey) == scriptedKeyId)
            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }) == "returned bytes")
            #expect(service.assertedKeyIds == [storedKeyId])

            // The retry attests the same replacement key, which then becomes
            // the key assertions use.
            let retried = try? await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            #expect(retried == retriedAttestation)
            #expect(service.keyGenerationCount == 1)
            #expect(service.attestedKeyIds == [scriptedKeyId, scriptedKeyId])
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == scriptedKeyId)
            #expect(harness.defaults.string(forKey: replacementKeyIdDefaultsKey) == nil)
        }

        @Test("a replacement key Apple's service rejects is discarded and the attested key stays")
        func rejectedReplacementKeepsAttestedKey() async {
            // `attestKey` and the key probe's assertion over the replacement
            // both answer `invalidKey`, and a later assertion succeeds.
            let service = ScriptedAppAttestService(
                supported: true,
                attestation: .invalidKey,
                assertion: .invalidKey,
                thenAssertion: .value(scriptedAssertion)
            )
            let harness = makeAdapter(service, storedKeyId: storedKeyId, attested: true)

            await expectCode("SCP-ATTEST-9023", from: "attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }

            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == storedKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == storedKeyId)
            #expect(harness.defaults.string(forKey: replacementKeyIdDefaultsKey) == nil)
            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }) == "returned bytes")
            #expect(service.assertedKeyIds == [scriptedKeyId, storedKeyId])
        }

        @Test("a replacement key Apple already attested is discarded, and assertions stay on the attested key")
        func alreadyAttestedReplacementKeepsAttestedKey() async {
            // An earlier attest generated the replacement, Apple attested it,
            // and that call never returned its attestation object, for
            // example because the process ended first. So `attestKey` now
            // answers `invalidKey`, and the key probe's assertion succeeds. No
            // published attestation names the replacement.
            let replacementKeyId = "replacement-app-attest-key"
            let nextAttestation = Data([0xA3])
            let service = ScriptedAppAttestService(
                supported: true,
                attestation: .invalidKey,
                thenAttestation: .value(nextAttestation)
            )
            let harness = makeAdapter(service, storedKeyId: storedKeyId, attested: true)
            harness.defaults.set(replacementKeyId, forKey: replacementKeyIdDefaultsKey)

            await expectCode("SCP-ATTEST-9021", from: "attest") { () async throws(ScpError) -> Data in
                try await harness.adapter.attest(challenge: challenge, deviceId: deviceId)
            }

            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == storedKeyId)
            #expect(harness.defaults.string(forKey: attestedKeyIdDefaultsKey) == storedKeyId)
            #expect(harness.defaults.string(forKey: replacementKeyIdDefaultsKey) == nil)
            #expect(service.keyGenerationCount == 0)
            #expect(await code(of: { () async throws(ScpError) -> Data in
                try await harness.adapter.assertRequest(requestHash: requestHash)
            }) == "returned bytes")
            #expect(service.assertedKeyIds == [replacementKeyId, storedKeyId])

            // The next attest generates another replacement, which becomes
            // the stored key only when an attestation naming it returns.
            let attestation = try? await harness.adapter.attest(challenge: Data(repeating: 0x02, count: 32), deviceId: deviceId)
            #expect(attestation == nextAttestation)
            #expect(service.attestedKeyIds == [replacementKeyId, scriptedKeyId])
            #expect(harness.defaults.string(forKey: keyIdDefaultsKey) == scriptedKeyId)
        }
    }

#endif // os(iOS) || os(macOS)
