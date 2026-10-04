#if os(iOS) || os(macOS)

    import CryptoKit
    import DeviceCheck
    import Foundation
    import os

    // DeviceAttestationProvider protocol is now defined by UniFFI in ScpBindings.swift.
    // The UniFFI-generated protocol has the same method signatures:
    //   attest(challenge: Data, deviceId: Data) async throws -> Data
    //   assertRequest(requestHash: Data) async throws -> Data
    // It also requires AnyObject conformance.

    // ---------------------------------------------------------------------------
    // Error type
    // ---------------------------------------------------------------------------

    /// Errors produced by `AppleDeviceAttestation`.
    public nonisolated enum AttestationError: Error, Sendable {
        /// The platform App Attest service returned an error no other case
        /// names: any error from `generateKey` other than
        /// `DCError.featureUnsupported`, `DCError.serverUnavailable` included;
        /// any error from `attestKey` other than `DCError.featureUnsupported`,
        /// `DCError.serverUnavailable` and `DCError.invalidKey`; or any error
        /// from `generateAssertion`, the key probe's included, other than
        /// `DCError.featureUnsupported`, `DCError.serverUnavailable` and
        /// `DCError.invalidKey`. Or the caller's task was cancelled
        /// while its App Attest call waited in the queue or for Apple's
        /// answer. For a cancellation the adapter throws no Swift
        /// `CancellationError`: it returns this case, with a message that
        /// begins `CancellationError:`.
        case serviceError(String)
        /// App Attest is unsupported: `DCAppAttestService` reports
        /// `isSupported == false`, or an App Attest call answers with
        /// `DCError.featureUnsupported`. This device cannot produce an App
        /// Attest attestation or assertion.
        ///
        /// A caller catches this case to learn that the device holds no
        /// hardware attestation signal. §9.3 of the security model spec,
        /// "Sybil resistance and identity uniqueness", states that the absence
        /// of a device attestation is expected and is not penalizing, so the
        /// caller presents no attestation rather than presenting a weaker one.
        case unsupported(String)
        /// No App Attest key ID is stored, because no `attest` call has
        /// stored one or because the adapter discarded a rejected key's ID
        /// (`keyRejected`); call `attest` first.
        case keyNotFound
        /// Apple already attested the stored App Attest key. Either the key
        /// carries this adapter's attestation record, so
        /// `attest(challenge:deviceId:)` called no App Attest method, or
        /// `attestKey` answered `DCError.invalidKey` for a key with no record
        /// and the key probe's assertion with that key succeeded, so the
        /// adapter wrote the record.
        ///
        /// Apple attests one key once: `DCError.h` lists a call to
        /// `attestKey:clientDataHash:completionHandler:` for a key already
        /// attested as one cause of `DCError.invalidKey`. The adapter keeps
        /// the key and its record, so `assertRequest(requestHash:)` keeps
        /// asserting with the attested key.
        case keyAlreadyAttested(String)
        /// Apple answered the `generateAssertion` call of
        /// `assertRequest(requestHash:)` with `DCError.invalidKey` for a stored
        /// key that carries no attestation record.
        ///
        /// `DCError.h` lists a call to
        /// `generateAssertion:clientDataHash:completionHandler:` with an
        /// unattested key and an App Attest service rejecting the key among
        /// the causes of that code, and a key with no record can
        /// meet either. An earlier `attest` that stored a generated key and
        /// failed before Apple attested it leaves an unattested key. An
        /// `attestKey` answer that arrived after its call ended, through the
        /// time limit or a cancellation, can leave a key Apple attested with
        /// no record, and Apple's service can later reject that key. The
        /// record cannot tell these apart, so the adapter keeps the key and
        /// asserts neither cause. The case name names the first cause only.
        case keyNotAttested(String)
        /// Apple's App Attest service rejected the stored key, and the
        /// adapter discarded its key ID and record. Either `generateAssertion`
        /// answered `DCError.invalidKey` for a stored key that carries an
        /// attestation record, or `attestKey` answered `DCError.invalidKey`
        /// for a key with no record and the key probe's assertion with that
        /// key answered `DCError.invalidKey` too.
        ///
        /// `DCError.h` lists an App Attest service rejecting the key as one
        /// cause of `DCError.invalidKey`. A later
        /// `attest(challenge:deviceId:)` generates a new key.
        case keyRejected(String)
        /// Apple answered `attestKey` or `generateAssertion`, the key probe's
        /// included, with `DCError.serverUnavailable`.
        ///
        /// For `attestKey`, `DCError.h` describes this code as a failed
        /// attempt to contact the App Attest service and instructs a caller
        /// to "try the attestation again later using the same key and the
        /// same value for the `clientDataHash` parameter", because "retrying
        /// with the same inputs helps to preserve the risk metric for a given
        /// device". `DCError.h` documents this code for `attestKey` only. The
        /// adapter keeps the key after either call, because it discards a key
        /// only when Apple's service rejects it.
        case serverUnavailable(String)
        /// An internal invariant was violated.
        case internalError(String)
        /// The attestation `challenge` or the assertion `requestHash` is not 32
        /// bytes, so it is not the binding digest `D` or the assertion digest
        /// `A` of `09-security-model.md` §9.3.1 that App Attest takes as
        /// `clientDataHash`.
        case invalidClientDataHash(String)
        /// App Attest did not answer one serialized call within
        /// `AppleDeviceAttestation.appAttestCallTimeLimit`, 25 seconds. The
        /// adapter runs the next queued call and discards any answer Apple
        /// gives the timed-out call later: that answer stores no key ID,
        /// writes no attestation record, discards no key ID, and reaches no
        /// caller.
        case timedOut(String)
    }

    extension AttestationError {
        /// The `ScpError` that carries this error across the UniFFI
        /// `DeviceAttestationProvider` callback, with one `SCP-ATTEST-` code
        /// per case, so Rust tells every case apart by its code.
        /// `crates/scp-ffi/common/src/error_codes.rs` registers each code.
        var scpError: ScpError {
            switch self {
            case let .serviceError(msg): .Identity(msg: msg, code: "SCP-ATTEST-9001")
            case let .unsupported(msg): .Identity(msg: msg, code: "SCP-ATTEST-9019")
            case .keyNotFound:
                .Identity(msg: "no App Attest key ID is stored; call attest first", code: "SCP-ATTEST-9020")
            case let .keyAlreadyAttested(msg): .Identity(msg: msg, code: "SCP-ATTEST-9021")
            case let .keyNotAttested(msg): .Identity(msg: msg, code: "SCP-ATTEST-9022")
            case let .keyRejected(msg): .Identity(msg: msg, code: "SCP-ATTEST-9023")
            case let .serverUnavailable(msg): .Identity(msg: msg, code: "SCP-ATTEST-9024")
            case let .internalError(msg): .Identity(msg: msg, code: "SCP-ATTEST-9025")
            case let .invalidClientDataHash(msg): .Identity(msg: msg, code: "SCP-ATTEST-9026")
            case let .timedOut(msg): .Identity(msg: msg, code: "SCP-ATTEST-9027")
            }
        }

        /// The case for an error an App Attest completion handler answered
        /// with: `unsupported` for `DCError.featureUnsupported`, which names the
        /// condition `SCP-ATTEST-9019` names, and `serviceError` for every
        /// other error.
        static func fromAppAttest(_ error: Error, call: String) -> AttestationError {
            if let dcError = error as? DCError, dcError.code == .featureUnsupported {
                return .unsupported(
                    "\(call) answered DCError.featureUnsupported, so App Attest cannot serve this call: "
                        + error.localizedDescription
                )
            }
            return .serviceError(error.localizedDescription)
        }
    }

    // ---------------------------------------------------------------------------
    // Storage key constants
    // ---------------------------------------------------------------------------

    private enum StorageKey {
        /// `UserDefaults` key under which the App Attest key ID is persisted.
        static let appAttestKeyId = "dev.limn.scp.appAttest.keyId"

        /// `UserDefaults` key under which the ID of a key Apple attested is
        /// persisted.
        ///
        /// Apple attests one key once, so this record is what makes `attest`
        /// call no App Attest method for the stored key, and it tells apart
        /// the two conditions `generateAssertion` answers `DCError.invalidKey`
        /// for. It holds a key ID rather than a flag, so a stale value cannot
        /// describe a key ID that replaced the one it names.
        static let attestedAppAttestKeyId = "dev.limn.scp.appAttest.attestedKeyId"
    }

    // ---------------------------------------------------------------------------
    // AppleDeviceAttestation
    // ---------------------------------------------------------------------------

    /// Apple platform implementation of `DeviceAttestationProvider`.
    ///
    /// ## Hardware path (iOS 14+ / macOS 11+, real device)
    ///
    /// Uses `DCAppAttestService` to generate a Secure Enclave-backed P-256 key
    /// and obtain an Apple-signed attestation certificate. The key ID is
    /// persisted in `UserDefaults` so subsequent calls reuse the same key.
    /// When `attestKey` returns an attestation object, the adapter records
    /// that key ID as attested, beside the key ID. Apple attests one key
    /// once, so an `attest` that reads a stored key carrying that record
    /// throws `SCP-ATTEST-9021` and calls no App Attest method.
    ///
    /// ## Key lifecycle on error (ADR-025 acceptance criterion 3)
    ///
    /// `classify(_:keyId:operation:)` maps each App Attest error to an
    /// `AttestationError` case and states which errors keep the stored key
    /// and which discard it. An `attestKey` answer of `DCError.invalidKey`
    /// leads to the key probe instead: `probeKey(_:after:call:)` asks
    /// `generateAssertion` for an assertion with that key over the
    /// client data `K` of `09-security-model.md` §9.3.1, and discards the
    /// assertion. Two answers discard the key ID and its record
    /// (`SCP-ATTEST-9023`): `generateAssertion` answering
    /// `DCError.invalidKey` for a key that carries an attestation record,
    /// and the key probe's assertion answering `DCError.invalidKey`.
    ///
    /// Attestation steps (per ADR-025 acceptance criterion 3):
    /// 1. `generateKey` — creates a Secure Enclave key via App Attest service.
    /// 2. `attestKey(_:clientDataHash:)` — requests Apple's attestation object,
    ///    with the 32-byte `challenge` as `clientDataHash`, unchanged. ADR-025
    ///    has the Rust core pass the binding digest `D` of
    ///    `09-security-model.md` §9.3.1 as `challenge`.
    /// 3. `generateAssertion(_:clientDataHash:)` — per-request proof of
    ///    possession, with the 32-byte `requestHash` as `clientDataHash`,
    ///    unchanged. ADR-025 has the Rust core pass the assertion digest `A`
    ///    of §9.3.1 as `requestHash`.
    ///
    /// When App Attest is supported, the adapter rejects a
    /// `challenge` or a `requestHash` that is not 32 bytes with
    /// `SCP-ATTEST-9026`, which `AttestationError.invalidClientDataHash` maps to,
    /// and otherwise hands it to App Attest as it arrived.
    ///
    /// ## Unavailable service (simulator, or a device without App Attest)
    ///
    /// When `DCAppAttestService.isSupported` is `false`, `attest` and
    /// `assertRequest` throw `ScpError.Identity` with code `SCP-ATTEST-9019`,
    /// which `AttestationError.unsupported` maps to. They throw the same code
    /// when `isSupported` is `true` but an App Attest call answers with
    /// `DCError.featureUnsupported`. The adapter mints
    /// no substitute token, because a locally fabricated token would assert a
    /// hardware guarantee that no hardware produced. §9.3 of the security model
    /// spec, "Sybil resistance and identity uniqueness", states that the
    /// absence of a device attestation is expected and is not penalizing, so
    /// the honest result is the typed error rather than a token.
    ///
    /// `isAppAttestSupported` reports `isSupported` only. When it reads
    /// `false`, `attest` and `assertRequest` throw `SCP-ATTEST-9019` without
    /// calling App Attest; when it reads `true`, either method can still throw
    /// `SCP-ATTEST-9019`, so a caller handles that code on every call.
    ///
    /// ## Thread safety
    ///
    /// `AppleDeviceAttestation` is `final` and conforms to `Sendable`. Its
    /// `UserDefaults` reads and writes are protected by `NSLock`.
    /// `callSerializer`, an actor, runs the App Attest calls of every `attest`
    /// and `assertRequest`, key generation included, one call at a time, in
    /// the order the serializer accepts them. Each call therefore reads the
    /// stored key ID after every preceding call ended. When every preceding
    /// call ended with Apple's answer, concurrent `attest` calls on a device
    /// with no stored key generate one key.
    /// `attest` and `assertRequest` check `isSupported` and the 32-byte
    /// length before they queue a call, so a call either check rejects waits
    /// for no other call.
    ///
    /// One serialized call is the whole of one `attest` (`generateKey`, when
    /// no key ID is stored, then `attestKey`, then the key probe's
    /// `generateAssertion` when `attestKey` answers `DCError.invalidKey`) or
    /// one `assertRequest` (`generateAssertion`). It ends at the first of
    /// four events: its key-ID read ends it without an App Attest call, with `SCP-ATTEST-9020`
    /// when an `assertRequest` reads no stored key ID and with
    /// `SCP-ATTEST-9021` when an `attest` reads a stored key that carries an
    /// attestation record; Apple's
    /// answers end it (every answer from its App Attest methods except a
    /// `generateKey` answer that carries a key ID and no error, which leads
    /// to `attestKey`, and an `attestKey` answer of `DCError.invalidKey`,
    /// which leads to the key probe); `appAttestCallTimeLimit` (25 seconds from
    /// the call's start) passes; or the caller's task is cancelled. On the
    /// time limit the caller gets `SCP-ATTEST-9027`; on
    /// cancellation it gets `SCP-ATTEST-9001`, through
    /// `AttestationError.serviceError`. Either way the serializer runs the
    /// next queued call, and a completion handler Apple runs after the call
    /// ended stores no key ID, writes no attestation record, discards no key
    /// ID, starts no further App Attest call, and reaches no caller. The
    /// answer that ends a call writes the attestation record, or discards
    /// the key ID, before the caller resumes and before the next call
    /// starts. An end that arrives while the adapter stores a key ID or
    /// hands App Attest a method takes effect when that step returns. An end
    /// that arrives while the adapter reads the stored key ID takes effect at
    /// once, and the adapter checks whether the call ended immediately before
    /// it stores a key ID or hands App Attest a method, so a call never
    /// starts an App Attest method after it ended. A caller
    /// cancelled while queued leaves the queue and never
    /// reaches Apple. After a timeout or a cancellation, Apple can still be
    /// working on the abandoned call while the next call runs, and the
    /// adapter neither waits for nor counts abandoned calls, so after `k`
    /// abandoned calls App Attest can hold up to `k + 1` outstanding calls.
    /// Each `generateKey` abandoned that way can leave a key no stored ID
    /// names, and the next `attest` generates another. The time limit
    /// starts when a call starts: time a caller spends queued counts
    /// against no limit.
    ///
    /// The lock and the serializer belong to the `UserDefaults` object that
    /// holds the key ID and the attestation record, not to one instance: `AppAttestKeyStateGuard`
    /// attaches one pair to that object, and every instance over that object
    /// takes that pair. `init()` reads `UserDefaults.standard`, which every
    /// instance in the process shares, so two instances built with `init()`
    /// run their App Attest calls in one order.
    ///
    /// See ADR-025 and the UniFFI `DeviceAttestationProvider` callback
    /// interface in `crates/scp-ffi/uniffi/src/lib.rs`, which this class
    /// conforms to.
    public final class AppleDeviceAttestation: DeviceAttestationProvider, @unchecked Sendable {
        // `@unchecked Sendable` is required because this class conforms to the
        // UniFFI `DeviceAttestationProvider` callback interface, whose Rust trait
        // requires `Send + Sync` (Rust) → `Sendable` (Swift). No Rust code holds or
        // calls that callback yet, so nothing injects this class into the Rust engine. Internal mutable
        // state (`UserDefaults`) is protected by `lock`; no reference
        // semantics escape across the FFI boundary. This is the same exception as
        // `MessageListenerAdapter`. See .docs/standards/swift.md §Sendable — UniFFI exception.

        private let service: DCAppAttestService
        private let defaults: UserDefaults
        private let lock: NSLock

        /// Runs one App Attest call at a time, so each call reads the stored
        /// key ID after every preceding call ended, and concurrent `attest`
        /// calls generate one key while every preceding call ended with
        /// Apple's answer.
        private let callSerializer: AppAttestCallSerializer

        /// How long one serialized App Attest call may run before its caller
        /// gets `SCP-ATTEST-9027`. Internal, not private, so a test can pin
        /// the value each initializer installs.
        let callTimeLimit: Duration

        /// The time limit on one serialized App Attest call: 25 seconds,
        /// below the 30-second `HANDLER_TIMEOUT` a runtime actor handler
        /// waits (ADR-025 acceptance criterion 3, the call-ordering item).
        /// The limit starts when the call starts, not when its caller
        /// queues. A caller whose call starts at once therefore gets
        /// `SCP-ATTEST-9027` within 25 seconds; a caller queued behind
        /// another call first waits for that call to end, up to 25 seconds
        /// per call ahead of it, so its whole wait can pass 30 seconds.
        static let appAttestCallTimeLimit: Duration = .seconds(25)

        /// The value of `DCAppAttestService.isSupported`, and nothing more.
        ///
        /// `false` on simulator and on devices without App Attest, where
        /// `attest` and `assertRequest` throw `SCP-ATTEST-9019`. `true` does
        /// not mean an attestation or assertion can be produced: App Attest
        /// can still answer `generateKey`, `attestKey` or `generateAssertion`
        /// with `DCError.featureUnsupported`, and the adapter then throws
        /// `SCP-ATTEST-9019` as well.
        public var isAppAttestSupported: Bool {
            service.isSupported
        }

        // MARK: - Init

        /// Creates an `AppleDeviceAttestation` using the shared
        /// `DCAppAttestService`.
        ///
        /// No I/O is performed during initialization; key generation is deferred
        /// to the first call to `attest(challenge:deviceId:)`.
        public init() {
            service = DCAppAttestService.shared
            defaults = UserDefaults.standard
            callTimeLimit = Self.appAttestCallTimeLimit
            let keyStateGuard = AppAttestKeyStateGuard.guarding(defaults)
            lock = keyStateGuard.lock
            callSerializer = keyStateGuard.callSerializer
        }

        /// Testing initializer that accepts injected dependencies.
        ///
        /// Used in unit tests to supply a mock `DCAppAttestService` subclass, an
        /// in-memory `UserDefaults` suite, and a time limit shorter than 25
        /// seconds. Every adapter built over one `defaults` object shares one
        /// lock and one serializer, as every adapter `init()` builds does.
        init(
            service: DCAppAttestService,
            defaults: UserDefaults,
            callTimeLimit: Duration = AppleDeviceAttestation.appAttestCallTimeLimit
        ) {
            self.service = service
            self.defaults = defaults
            self.callTimeLimit = callTimeLimit
            let keyStateGuard = AppAttestKeyStateGuard.guarding(defaults)
            lock = keyStateGuard.lock
            callSerializer = keyStateGuard.callSerializer
        }

        /// The number of callers waiting in this adapter's serializer queue,
        /// not counting the call it is running.
        func waitingAppAttestCallCount() async -> Int {
            await callSerializer.waitingCallCount
        }

        /// Report whether this adapter and `other` share one lock and one
        /// serializer, which every two adapters over one `UserDefaults` object
        /// do.
        func sharesKeyState(with other: AppleDeviceAttestation) -> Bool {
            lock === other.lock && callSerializer === other.callSerializer
        }

        // MARK: - DeviceAttestationProvider

        /// The `DeviceAttestationProvider` callback method that returns an
        /// attestation. No Rust code holds or calls the callback yet, so only
        /// Swift callers reach this method.
        ///
        /// The UniFFI callback declares `ScpError` as its error type. The
        /// generated glue lowers a thrown `ScpError` into an error value that
        /// a Rust caller receives, and hands any other thrown type to Rust as an
        /// unexpected callback error, which panics on the Rust side. This
        /// method therefore throws `ScpError` only: it translates each
        /// `AttestationError` through `AttestationError.scpError`, and
        /// `attestReportingAttestationError(challenge:deviceId:)` declares
        /// `throws(AttestationError)`, so the compiler rejects any other type.
        ///
        /// - Throws: `ScpError.Identity` carrying `SCP-ATTEST-9019` for
        ///   `AttestationError.unsupported`, `SCP-ATTEST-9026` for
        ///   `AttestationError.invalidClientDataHash`, `SCP-ATTEST-9021` for
        ///   `AttestationError.keyAlreadyAttested`, `SCP-ATTEST-9023` for
        ///   `AttestationError.keyRejected`, `SCP-ATTEST-9024` for
        ///   `AttestationError.serverUnavailable`, `SCP-ATTEST-9001` for
        ///   `AttestationError.serviceError`, `SCP-ATTEST-9025` for
        ///   `AttestationError.internalError`, or `SCP-ATTEST-9027` for
        ///   `AttestationError.timedOut`, in the cases
        ///   `attestReportingAttestationError(challenge:deviceId:)` lists.
        public func attest(challenge: Data, deviceId: Data) async throws(ScpError) -> Data {
            do throws(AttestationError) {
                return try await attestReportingAttestationError(challenge: challenge, deviceId: deviceId)
            } catch {
                throw error.scpError
            }
        }

        /// The `DeviceAttestationProvider` callback method that returns an
        /// assertion. No Rust code holds or calls the callback yet. It throws `ScpError` only, for the
        /// reason `attest(challenge:deviceId:)` states.
        ///
        /// - Throws: `ScpError.Identity` carrying `SCP-ATTEST-9019` for
        ///   `AttestationError.unsupported`, `SCP-ATTEST-9026` for
        ///   `AttestationError.invalidClientDataHash`, `SCP-ATTEST-9020` for
        ///   `AttestationError.keyNotFound`, `SCP-ATTEST-9022` for
        ///   `AttestationError.keyNotAttested`, `SCP-ATTEST-9023` for
        ///   `AttestationError.keyRejected`, `SCP-ATTEST-9024` for
        ///   `AttestationError.serverUnavailable`, `SCP-ATTEST-9001` for
        ///   `AttestationError.serviceError`, `SCP-ATTEST-9025` for
        ///   `AttestationError.internalError`, or `SCP-ATTEST-9027` for
        ///   `AttestationError.timedOut`, in the cases
        ///   `assertRequestReportingAttestationError(requestHash:)` lists.
        public func assertRequest(requestHash: Data) async throws(ScpError) -> Data {
            do throws(AttestationError) {
                return try await assertRequestReportingAttestationError(requestHash: requestHash)
            } catch {
                throw error.scpError
            }
        }

        /// Generate an attestation for the given challenge.
        ///
        /// On a real device with App Attest available:
        /// 1. Checks that `challenge` is 32 bytes, before any App Attest call.
        /// 2. Retrieves or generates the App Attest key ID. A stored key that
        ///    carries an attestation record ends the call here with
        ///    `AttestationError.keyAlreadyAttested`, before any App Attest
        ///    call.
        /// 3. Calls `DCAppAttestService.attestKey(_:clientDataHash:)` with
        ///    `challenge` as `clientDataHash`, unchanged. When it answers
        ///    `DCError.invalidKey`, runs the key probe
        ///    `probeKey(_:after:call:)` inside the same serialized call and
        ///    throws the case the probe's answer gives.
        /// 4. Records the key ID as attested and returns the raw CBOR
        ///    attestation object Apple signed.
        ///
        /// ADR-025 acceptance criterion 3 has the Rust core pass the binding
        /// digest `D` of `09-security-model.md` §9.3.1 as `challenge`. This
        /// adapter does not read `deviceId`, because `D` already binds the
        /// identity.
        ///
        /// When `DCAppAttestService.isSupported` is `false`, as on simulator,
        /// this method throws `AttestationError.unsupported`, calls no App
        /// Attest method, and returns no bytes. When `generateKey`, `attestKey`
        /// or the key probe's `generateAssertion` answers with
        /// `DCError.featureUnsupported`, it throws the same error after that
        /// call, and returns no bytes.
        ///
        /// - Parameters:
        ///   - challenge: The 32-byte §9.3.1 binding digest `D`.
        ///   - deviceId: Not read by this adapter.
        /// - Returns: The raw CBOR attestation object Apple signed.
        /// - Throws: `AttestationError.unsupported` when
        ///   `DCAppAttestService.isSupported` is `false`, or when `generateKey`,
        ///   `attestKey` or the key probe's `generateAssertion` answers with
        ///   `DCError.featureUnsupported`.
        ///   `AttestationError.invalidClientDataHash` when App Attest is supported
        ///   and `challenge` is not 32 bytes; this method then generates no
        ///   key and calls no App Attest method.
        ///   `AttestationError.keyAlreadyAttested` when the stored key carries
        ///   an attestation record; this method then calls no App Attest
        ///   method and keeps the key and its record. Also when `attestKey`
        ///   answers with `DCError.invalidKey` and the key probe's assertion
        ///   succeeds; this method then keeps the key and records it as
        ///   attested.
        ///   `AttestationError.keyRejected` when `attestKey` and the key
        ///   probe's assertion both answer with `DCError.invalidKey`; this
        ///   method then discards the key ID.
        ///   `AttestationError.serverUnavailable` when `attestKey` answers
        ///   with `DCError.serverUnavailable`; this method keeps the key, so a
        ///   retry uses the same key, as `DCError.h` instructs. Also when the
        ///   key probe's assertion after an `attestKey` answer of
        ///   `DCError.invalidKey` answers with `DCError.serverUnavailable`;
        ///   this method then keeps the key.
        ///   `AttestationError.serviceError` when `generateKey` answers with
        ///   any error other than `DCError.featureUnsupported`,
        ///   `DCError.serverUnavailable` included, when `attestKey` or the key
        ///   probe's assertion answers with an error no other case names, or
        ///   when the caller's task is cancelled while the call is queued or
        ///   outstanding.
        ///   `AttestationError.internalError` when `generateKey`, `attestKey`
        ///   or the key probe's assertion answers with neither a value nor an
        ///   error. After `attestKey` answers, every case but `keyRejected`
        ///   keeps the key.
        ///   `AttestationError.timedOut` when `generateKey`, `attestKey` and
        ///   the key probe's assertion together take longer than
        ///   `appAttestCallTimeLimit`.
        func attestReportingAttestationError(
            challenge: Data,
            deviceId _: Data
        ) async throws(AttestationError) -> Data {
            guard service.isSupported else {
                throw AttestationError.unsupported(
                    "DCAppAttestService.isSupported is false on this device, so App Attest cannot "
                        + "produce an attestation. This adapter mints no substitute token."
                )
            }
            guard challenge.count == 32 else {
                throw AttestationError.invalidClientDataHash(
                    "the attestation challenge is \(challenge.count) bytes; App Attest takes the "
                        + "32-byte binding digest D of 09-security-model.md §9.3.1 as clientDataHash"
                )
            }

            // The two checks above run before the call is queued, so a call
            // they reject waits for no other call. The key ID is read inside
            // the serialized call, so it follows every preceding call's write,
            // and concurrent first calls generate one key while every
            // preceding call ended with Apple's answer.
            let outcome = await callSerializer.run(timeLimit: callTimeLimit) { [self] call in
                if let keyId = loadKeyId() {
                    // Apple attests one key once, so a key this adapter
                    // recorded as attested goes to no App Attest call.
                    if isKeyAttested(keyId) {
                        call.end(with: .failure(.keyAlreadyAttested(
                            "App Attest already attested the stored key, and Apple attests one key once, "
                                + "so this adapter called no App Attest method"
                        )))
                        return
                    }
                    call.issue {
                        requestAttestation(keyId: keyId, challenge: challenge, call: call)
                    }
                    return
                }
                call.issue {
                    service.generateKey { [self] keyId, error in
                        if let error {
                            call.end(with: .failure(.fromAppAttest(error, call: "generateKey")))
                        } else if let keyId {
                            // A key ID that arrives after the call ended is
                            // discarded: it is neither stored nor attested. The
                            // store and the `attestKey` call run inside one
                            // `issue`, so an end that arrives between them takes
                            // effect after `attestKey` started.
                            call.issue {
                                storeKeyId(keyId)
                                requestAttestation(keyId: keyId, challenge: challenge, call: call)
                            }
                        } else {
                            call.end(with: .failure(.internalError("generateKey returned neither keyId nor error")))
                        }
                    }
                }
            }
            return try outcome.get()
        }

        /// Generate a per-request assertion for a previously attested key.
        ///
        /// On a real device with App Attest available, calls
        /// `DCAppAttestService.generateAssertion(_:clientDataHash:)`. The
        /// assertion binds the request hash to the stored App Attest key.
        ///
        /// When `DCAppAttestService.isSupported` is `false`, as on simulator,
        /// this method throws `AttestationError.unsupported`, calls no App
        /// Attest method, and returns no bytes. When `generateAssertion` answers
        /// with `DCError.featureUnsupported`, it throws the same error after
        /// that call, and returns no bytes.
        ///
        /// - Parameter requestHash: The 32-byte assertion digest
        ///   `A = SHA-256("SCP-DEVICE-ASSERTION-V1:" ‖ BE32(len(m)) ‖ m)` of
        ///   `09-security-model.md` §9.3.1 over the caller's request bytes `m`,
        ///   never `SHA-256(m)` and never `m` itself. The method passes it to
        ///   `generateAssertion` as `clientDataHash` unchanged.
        /// - Returns: The CBOR assertion bytes App Attest returns.
        /// - Throws: `AttestationError.unsupported` when
        ///   `DCAppAttestService.isSupported` is `false`, or when
        ///   `generateAssertion` answers with `DCError.featureUnsupported`.
        ///   `AttestationError.invalidClientDataHash` when App Attest is supported
        ///   and `requestHash` is not 32 bytes; this method then calls no App
        ///   Attest method.
        ///   `AttestationError.keyNotFound` when no key ID is stored, because
        ///   no `attest` call has stored one or because a `keyRejected` answer
        ///   discarded it and no later `attest` stored a new one.
        ///   `AttestationError.keyNotAttested` when `generateAssertion`
        ///   answers with `DCError.invalidKey` for a key that carries no
        ///   attestation record, which names either an unattested key or a
        ///   rejected key whose record was never written; this method keeps
        ///   the key.
        ///   `AttestationError.keyRejected` when `generateAssertion` answers
        ///   with `DCError.invalidKey` for a key that carries an attestation
        ///   record; this method discards the key ID and its record.
        ///   `AttestationError.serverUnavailable` when `generateAssertion`
        ///   answers with `DCError.serverUnavailable`; this method keeps the
        ///   key.
        ///   `AttestationError.serviceError` when `generateAssertion` answers
        ///   with any other error, or when the caller's task is cancelled while
        ///   the call is queued or outstanding.
        ///   `AttestationError.internalError` when `generateAssertion` answers
        ///   with neither an assertion nor an error.
        ///   `AttestationError.timedOut` when `generateAssertion` does not
        ///   answer within `appAttestCallTimeLimit`.
        func assertRequestReportingAttestationError(
            requestHash: Data
        ) async throws(AttestationError) -> Data {
            guard service.isSupported else {
                throw AttestationError.unsupported(
                    "DCAppAttestService.isSupported is false on this device, so App Attest cannot "
                        + "produce an assertion. This adapter mints no substitute token."
                )
            }
            guard requestHash.count == 32 else {
                throw AttestationError.invalidClientDataHash(
                    "the assertion request hash is \(requestHash.count) bytes; App Attest takes the "
                        + "32-byte assertion digest A of 09-security-model.md §9.3.1 as clientDataHash"
                )
            }

            // The key ID is read inside the serialized call for the reason
            // `attestReportingAttestationError(challenge:deviceId:)` states.
            let outcome = await callSerializer.run(timeLimit: callTimeLimit) { [self] call in
                guard let keyId = loadKeyId() else {
                    call.end(with: .failure(.keyNotFound))
                    return
                }
                call.issue {
                    service.generateAssertion(keyId, clientDataHash: requestHash) { [self] assertion, error in
                        // `classify` reads the attestation record and may
                        // discard the key ID, so it runs only when this
                        // answer ends the call.
                        call.end {
                            if let error {
                                return .failure(classify(error, keyId: keyId, operation: .assertion))
                            }
                            if let assertion {
                                return .success(assertion)
                            }
                            return .failure(.internalError("generateAssertion returned neither assertion nor error"))
                        }
                    }
                }
            }
            return try outcome.get()
        }

        // MARK: - Private helpers

        /// Ask App Attest to attest `keyId` over `challenge`, and end `call`
        /// with its answer.
        ///
        /// `call` ends at most once, so an answer that arrives after the time
        /// limit or the caller's cancellation ended `call` reaches no caller.
        ///
        /// The attestation record is written only when Apple's answer ends
        /// `call`: here when the attestation object reaches the caller, and
        /// in `probeKey(_:after:call:)` when the key probe shows Apple
        /// attested the key. An answer of `DCError.invalidKey` does not end
        /// `call`; it hands the key probe to `issue(_:)`, which starts the
        /// probe only while `call` is open.
        private func requestAttestation(keyId: String, challenge: Data, call: AppAttestCall) {
            service.attestKey(keyId, clientDataHash: challenge) { [self] attestation, error in
                if let error, (error as? DCError)?.code == .invalidKey {
                    call.issue {
                        probeKey(keyId, after: error, call: call)
                    }
                    return
                }
                call.end {
                    if let error {
                        return .failure(classify(error, keyId: keyId, operation: .attestation))
                    }
                    if let attestation {
                        markKeyAttested(keyId)
                        return .success(attestation)
                    }
                    return .failure(.internalError("attestKey returned neither attestation nor error"))
                }
            }
        }

        // MARK: - App Attest error classification

        /// Which App Attest call produced an error.
        ///
        /// Apple returns `DCError.invalidKey` for three different conditions,
        /// and which call raised it narrows those three.
        private enum AppAttestOperation {
            case attestation
            case assertion

            /// The App Attest method this operation calls.
            var method: String {
                switch self {
                case .attestation: "attestKey"
                case .assertion: "generateAssertion"
                }
            }
        }

        /// Translate an error `attestKey` or `generateAssertion` answered with
        /// into an `AttestationError`, and discard the key ID when that error
        /// says Apple's service rejected the key.
        ///
        /// **Criterion this method applies.** `DCError.h` lists three
        /// conditions behind `DCErrorInvalidKey`: a call to
        /// `attestKey:clientDataHash:completionHandler:` for a key already
        /// attested, a call to
        /// `generateAssertion:clientDataHash:completionHandler:` with an
        /// unattested key, and an App Attest service rejecting the key.
        ///
        /// | Call | Error | Record | Case | Key |
        /// | --- | --- | --- | --- | --- |
        /// | `generateAssertion` | `invalidKey` | none | `keyNotAttested` | kept |
        /// | `generateAssertion` | `invalidKey` | present | `keyRejected` | discarded |
        /// | either | `serverUnavailable` | any | `serverUnavailable` | kept |
        /// | either | `featureUnsupported` | any | `unsupported` | kept |
        /// | either | any other | any | `serviceError` | kept |
        ///
        /// `generateKey` errors do not reach this method:
        /// `AttestationError.fromAppAttest(_:call:)` maps them, so a
        /// `generateKey` answer of `DCError.serverUnavailable` or
        /// `DCError.invalidKey` gives `serviceError`.
        ///
        /// An `attestKey` answer of `invalidKey` does not reach this method
        /// either. `attest` hands `attestKey` only a key with no attestation
        /// record, so a record cannot tell apart the two conditions that
        /// answer can name: a key Apple attested whose record was never
        /// written, and a key Apple's service rejected.
        /// `requestAttestation(keyId:challenge:call:)` therefore hands that
        /// answer to the key probe, `probeKey(_:after:call:)`, whose own
        /// table says what each probe answer gives. A key with no record that
        /// the `generateAssertion` call of `assertRequest(requestHash:)`
        /// answers with `invalidKey` is either unattested or a rejected key
        /// whose record was never written, so the adapter keeps it and
        /// reports `keyNotAttested`, whose message names both causes.
        ///
        /// **What makes the attestation record a sound input.** The record
        /// describes the key App Attest holds only while no other call writes
        /// it. `callSerializer` runs one call at a time, and this method runs
        /// only inside the `AppAttestCall.end(_:)` body of the answer that
        /// ends its call, before the next call starts, so every read here
        /// follows every write a preceding call made.
        private func classify(_ error: Error, keyId: String, operation: AppAttestOperation) -> AttestationError {
            switch (error as? DCError)?.code {
            case .serverUnavailable:
                return .serverUnavailable(
                    "\(operation.method) answered DCError.serverUnavailable; this adapter kept the key "
                        + "for a retry: \(error.localizedDescription)"
                )
            case .invalidKey where operation == .assertion:
                guard isKeyAttested(keyId) else {
                    return .keyNotAttested(
                        "App Attest refused an assertion with the stored key, which carries no attestation "
                            + "record, so this adapter kept the key; the key is either unattested or rejected: "
                            + "\(error.localizedDescription)"
                    )
                }
                return rejectKey(keyId, error)
            default:
                return .fromAppAttest(error, call: operation.method)
            }
        }

        /// The client data of the key probe's assertion: the key-probe input
        /// `K = SHA-256("SCP-APP-ATTEST-KEY-PROBE-V1")` of
        /// `09-security-model.md` §9.3.1, whose separator §9.18.2 registers.
        /// `K`'s preimage differs from the preimages of the binding digest
        /// `D` and the assertion digest `A`, so `K` equals neither short of a
        /// SHA-256 collision. Apple signs it with the stored key, and this
        /// adapter discards that assertion.
        private static let keyProbeClientDataHash = Data(SHA256.hash(data: Data("SCP-APP-ATTEST-KEY-PROBE-V1".utf8)))

        /// Ask Apple for an assertion over `keyProbeClientDataHash` with a
        /// key `attestKey` answered `DCError.invalidKey` for, discard that
        /// assertion, and end `call` with what Apple's answer shows.
        ///
        /// | Probe answer | Case | Key |
        /// | --- | --- | --- |
        /// | an assertion | `keyAlreadyAttested` | kept, recorded as attested |
        /// | `invalidKey` | `keyRejected` | discarded |
        /// | `serverUnavailable` | `serverUnavailable` | kept |
        /// | `featureUnsupported` | `unsupported` | kept |
        /// | any other error | `serviceError` | kept |
        /// | neither an assertion nor an error | `internalError` | kept |
        ///
        /// The probe runs inside `call`, under the time limit of the `attest`
        /// that led to it, and its answer writes the record or discards the
        /// key ID only when that answer ends `call`, so an answer that
        /// arrives after the time limit or a cancellation writes neither.
        private func probeKey(_ keyId: String, after attestError: Error, call: AppAttestCall) {
            service.generateAssertion(keyId, clientDataHash: Self.keyProbeClientDataHash) { [self] assertion, probeError in
                call.end {
                    if let probeError {
                        switch (probeError as? DCError)?.code {
                        case .invalidKey:
                            return .failure(rejectKey(keyId, attestError))
                        case .serverUnavailable:
                            return .failure(.serverUnavailable(
                                "attestKey answered DCError.invalidKey, and the key probe's generateAssertion "
                                    + "answered DCError.serverUnavailable; "
                                    + "this adapter kept the key for a retry: \(probeError.localizedDescription)"
                            ))
                        case .featureUnsupported:
                            return .failure(.fromAppAttest(probeError, call: "generateAssertion"))
                        default:
                            return .failure(.serviceError(
                                "attestKey answered DCError.invalidKey, and the key probe's generateAssertion "
                                    + "failed; this adapter kept the key: "
                                    + probeError.localizedDescription
                            ))
                        }
                    }
                    if assertion != nil {
                        markKeyAttested(keyId)
                        return .failure(.keyAlreadyAttested(
                            "attestKey answered DCError.invalidKey and an assertion with the stored key succeeded; "
                                + "this adapter kept the key and recorded it as "
                                + "attested: \(attestError.localizedDescription)"
                        ))
                    }
                    return .failure(.internalError(
                        "the key probe's generateAssertion returned neither assertion nor error"
                    ))
                }
            }
        }

        /// Discard a key Apple's App Attest service rejected, and return the
        /// case that reports it.
        private func rejectKey(_ keyId: String, _ error: Error) -> AttestationError {
            forgetKeyId(keyId)
            return .keyRejected(
                "App Attest rejected this device's key, and this adapter discarded its key "
                    + "ID, so a later attest generates a new key: \(error.localizedDescription)"
            )
        }

        // MARK: Persistence (UserDefaults)

        /// Load the stored App Attest key ID from `UserDefaults`.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// - Returns: The stored key ID, or `nil` if none has been generated yet.
        private func loadKeyId() -> String? {
            lock.lock()
            defer { lock.unlock() }
            return defaults.string(forKey: StorageKey.appAttestKeyId)
        }

        /// Persist an App Attest key ID to `UserDefaults`.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// - Parameter keyId: The key ID returned by
        ///   `DCAppAttestService.generateKey`.
        private func storeKeyId(_ keyId: String) {
            lock.lock()
            defer { lock.unlock() }
            defaults.set(keyId, forKey: StorageKey.appAttestKeyId)
        }

        /// Record that Apple attested `keyId`.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// - Parameter keyId: A key ID whose `attestKey` call returned an
        ///   attestation object, or whose key probe assertion succeeded after
        ///   `attestKey` answered `DCError.invalidKey`. The record is written
        ///   only while `keyId` is still the stored key ID, so it never names
        ///   a key ID this adapter no longer stores.
        private func markKeyAttested(_ keyId: String) {
            lock.lock()
            defer { lock.unlock() }
            guard defaults.string(forKey: StorageKey.appAttestKeyId) == keyId else { return }
            defaults.set(keyId, forKey: StorageKey.attestedAppAttestKeyId)
        }

        /// Report whether Apple attested `keyId`.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// - Parameter keyId: A key ID an App Attest call named.
        /// - Returns: `true` when this adapter recorded an attestation for that
        ///   exact key ID.
        private func isKeyAttested(_ keyId: String) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return defaults.string(forKey: StorageKey.attestedAppAttestKeyId) == keyId
        }

        /// Remove the stored App Attest key ID and its attestation record,
        /// unless another key ID replaced it.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// - Parameter keyId: A key ID Apple's App Attest service rejected.
        ///   Removing only this value keeps a key ID stored after it in place.
        private func forgetKeyId(_ keyId: String) {
            lock.lock()
            defer { lock.unlock() }
            guard defaults.string(forKey: StorageKey.appAttestKeyId) == keyId else { return }
            defaults.removeObject(forKey: StorageKey.appAttestKeyId)
            defaults.removeObject(forKey: StorageKey.attestedAppAttestKeyId)
        }
    }

    // ---------------------------------------------------------------------------
    // App Attest key-state guard
    // ---------------------------------------------------------------------------

    /// The lock and the call serializer that order every App Attest call over
    /// one `UserDefaults` object.
    ///
    /// The stored key ID lives in that object, so two adapters over it race
    /// unless they share one order. `guarding(_:)` keeps the pair as an
    /// Objective-C associated object of that `UserDefaults` object, so the
    /// pair lives exactly as long as that object and no Swift global holds it.
    private final class AppAttestKeyStateGuard {
        let lock = NSLock()
        let callSerializer = AppAttestCallSerializer()

        /// Return the pair attached to `defaults`, attaching a new pair first
        /// when `defaults` carries none.
        ///
        /// `objc_sync_enter` on `defaults` makes the read and the attach one
        /// step, so two adapters built at once over one object take one pair.
        static func guarding(_ defaults: UserDefaults) -> AppAttestKeyStateGuard {
            // The class metadata address is unique in the process and never
            // moves, which makes it a stable association key.
            let key = unsafeBitCast(AppAttestKeyStateGuard.self, to: UnsafeRawPointer.self)
            objc_sync_enter(defaults)
            defer { objc_sync_exit(defaults) }
            if let existing = objc_getAssociatedObject(defaults, key) as? AppAttestKeyStateGuard {
                return existing
            }
            let created = AppAttestKeyStateGuard()
            objc_setAssociatedObject(defaults, key, created, .OBJC_ASSOCIATION_RETAIN)
            return created
        }
    }

    // ---------------------------------------------------------------------------
    // App Attest call serialization
    // ---------------------------------------------------------------------------

    /// Runs App Attest calls one at a time, in the order it accepts them.
    ///
    /// The serializer accepts a call when the actor runs that caller's
    /// `run(timeLimit:_:)` job. Swift's default actor executor does not
    /// promise to run jobs in the order callers made them: it may run a
    /// later, higher-priority caller's job before an earlier, lower-priority
    /// one. So the order App Attest sees is the acceptance order, not the
    /// order in which callers called `attest` or `assertRequest`. Neither the
    /// serializer's mutual exclusion nor the one-key guarantee, which holds
    /// while every call ends with Apple's answer, depends on that order.
    ///
    /// **Why serialization, rather than a lock around the key-ID read:**
    /// `generateKey` answers through a completion handler, so a lock cannot be
    /// held from the read that finds no stored key ID to the write that stores
    /// the generated one. Two first `attest` calls that each held the lock only
    /// for the read would both find no key ID and generate one key each.
    /// Running each call, from the key-ID read until the call ends, before
    /// the next call starts makes each read follow every preceding call's
    /// write.
    ///
    /// **Bound and cancellation** (ADR-025 acceptance criterion 3): a running
    /// call ends at the first of its key-ID read ending it without an App
    /// Attest call (an `assertRequest` that finds no stored key ID, or an
    /// `attest` that finds a stored key carrying an attestation record),
    /// Apple's answer, `timeLimit`, or the caller's cancellation, and the
    /// serializer then starts the next queued call.
    /// `AppAttestCall` discards whatever Apple answers after that. A caller
    /// cancelled while queued leaves the queue without reaching Apple. Time
    /// spent queued counts against no limit: each call ahead of a caller runs
    /// for at most `timeLimit`, so a caller behind `n` calls waits up to
    /// `n + 1` times `timeLimit` in all.
    private actor AppAttestCallSerializer {
        /// Whether a call holds the serializer.
        private var running = false
        /// Callers waiting for the serializer, first in line first. Each
        /// continuation resumes with `true` when its caller's call starts,
        /// or `false` when that caller was cancelled first.
        private var waiting: [(ticket: UInt64, turn: CheckedContinuation<Bool, Never>)] = []
        private var nextTicket: UInt64 = 0

        /// The number of callers waiting, not counting the running call.
        var waitingCallCount: Int {
            waiting.count
        }

        /// Wait for every call this serializer accepted earlier to end, then
        /// run one call: `start` hands it to App Attest, and the call ends at
        /// the first of `start` ending it without App Attest (an
        /// `assertRequest` that reads no stored key ID, or an `attest` that
        /// reads a stored key carrying an attestation record), Apple's
        /// answer, `timeLimit`, or the caller's cancellation.
        ///
        /// - Parameter start: Starts the call's App Attest work and ends the
        ///   `AppAttestCall` it receives, from Apple's completion handlers or,
        ///   when it calls no App Attest method, directly.
        /// - Returns: What ended the call; a cancelled caller receives
        ///   `AppAttestCall.cancelledOutcome`, whether it was queued or
        ///   running.
        func run(
            timeLimit: Duration,
            _ start: @Sendable @escaping (AppAttestCall) -> Void
        ) async -> Result<Data, AttestationError> {
            let ticket = nextTicket
            nextTicket &+= 1
            let admitted = await withTaskCancellationHandler {
                await admit(ticket)
            } onCancel: {
                Task { await self.withdraw(ticket) }
            }
            guard admitted else {
                return AppAttestCall.cancelledOutcome
            }
            let outcome = await AppAttestCall().run(timeLimit: timeLimit, start)
            startNextCall()
            return outcome
        }

        /// Return `true` once `ticket`'s call holds the serializer, or `false`
        /// when its caller is cancelled while it waits. A caller cancelled
        /// before it reaches the serializer is admitted like any other, and
        /// `AppAttestCall.run` ends its call before the call reads a key ID
        /// or reaches Apple, so the serializer keeps one cancellation check.
        private func admit(_ ticket: UInt64) async -> Bool {
            if !running {
                running = true
                return true
            }
            return await withCheckedContinuation { turn in
                waiting.append((ticket, turn))
            }
        }

        /// Remove `ticket` from the queue and end its wait. A ticket already
        /// running or already gone is left alone: the running call ends
        /// through its own cancellation handler.
        private func withdraw(_ ticket: UInt64) {
            guard let index = waiting.firstIndex(where: { $0.ticket == ticket }) else {
                return
            }
            waiting.remove(at: index).turn.resume(returning: false)
        }

        /// Hand the serializer to the first waiting caller, or free it.
        private func startNextCall() {
            if waiting.isEmpty {
                running = false
            } else {
                waiting.removeFirst().turn.resume(returning: true)
            }
        }
    }

    /// One App Attest call the serializer runs, which ends exactly once.
    ///
    /// A key-ID read that ends the call without an App Attest call (no stored
    /// key ID in `assertRequest`, or a stored key carrying an attestation
    /// record in `attest`), Apple's answer, the time limit and the caller's
    /// cancellation each try to end the call; the first one ends it, and
    /// each later one does nothing. Apple's answer ends the call through
    /// `end(_:)`, whose body writes the attestation record or discards a key
    /// ID only when that answer is the first end, and before the caller
    /// resumes, so a late answer writes neither. The
    /// adapter stores a key ID and hands App Attest a method only inside
    /// `issue(_:)`, which runs nothing once the call ended. An end that
    /// arrives while an `issue(_:)` body runs takes effect, and resumes the
    /// caller, when that body returns, so every key ID a call stores and every
    /// App Attest method it starts comes before the call ends. The key-ID
    /// read runs outside `issue(_:)`: an end that arrives during it takes
    /// effect at once, and the `issue(_:)` after the read then starts nothing.
    private final class AppAttestCall: Sendable {
        /// What ending the call hands its caller.
        private struct Delivery: Sendable {
            let waiter: CheckedContinuation<Result<Data, AttestationError>, Never>
            let timer: Task<Void, Never>?
            let outcome: Result<Data, AttestationError>

            func perform() {
                timer?.cancel()
                waiter.resume(returning: outcome)
            }
        }

        /// The call's mutable state. `OSAllocatedUnfairLock` guards it, so
        /// the class conforms to `Sendable` with the compiler checking every
        /// access.
        private struct State: Sendable {
            /// The outcome the first `end(with:)` or `end(_:)` set; `nil`
            /// while the call is open or while an `end(_:)` body computes it.
            var outcome: Result<Data, AttestationError>?
            /// Whether an `end(_:)` body that won the end is computing
            /// `outcome`. Every other end does nothing once this is set.
            var closing = false
            /// Whether the caller has received `outcome`.
            var delivered = false
            /// The number of `issue(_:)` bodies running.
            var issuing = 0
            var waiter: CheckedContinuation<Result<Data, AttestationError>, Never>?
            var timer: Task<Void, Never>?

            /// Whether no end has happened or begun.
            var isOpen: Bool {
                outcome == nil && !closing
            }

            /// Take what resumes the caller when the call ended, no
            /// `issue(_:)` body runs, and `run` installed the caller's
            /// continuation; otherwise return `nil`.
            mutating func takeDelivery() -> Delivery? {
                guard let outcome, !delivered, issuing == 0, let waiter else {
                    return nil
                }
                delivered = true
                let delivery = Delivery(waiter: waiter, timer: timer, outcome: outcome)
                self.waiter = nil
                timer = nil
                return delivery
            }
        }

        private let state = OSAllocatedUnfairLock(initialState: State())

        /// What a caller cancelled while queued or running receives:
        /// `AttestationError.serviceError`, whose message begins
        /// `CancellationError:`. No Swift `CancellationError` is thrown; the
        /// serializer returns this outcome in its place.
        static let cancelledOutcome: Result<Data, AttestationError> = .failure(.serviceError(
            "CancellationError: the caller's task was cancelled before App Attest answered; "
                + "the adapter discards any later answer"
        ))

        /// Start the call through `start` and wait until it ends. A caller
        /// cancelled before the call starts never reaches `start`.
        func run(
            timeLimit: Duration,
            _ start: @Sendable (AppAttestCall) -> Void
        ) async -> Result<Data, AttestationError> {
            await withTaskCancellationHandler {
                await withCheckedContinuation { continuation in
                    let open: Bool = state.withLock { state in
                        state.waiter = continuation
                        guard state.isOpen else {
                            return false
                        }
                        state.timer = Task { [self] in
                            do {
                                try await Task.sleep(for: timeLimit)
                            } catch {
                                return
                            }
                            end(with: .failure(.timedOut(
                                "App Attest did not answer within \(timeLimit); the adapter runs the next "
                                    + "queued call and discards any later answer"
                            )))
                        }
                        return true
                    }
                    // A call that ended before the lock above reads no key
                    // ID and starts nothing; its caller receives the outcome
                    // here. After the lock, `start` hands App Attest each
                    // method through `issue(_:)`, which starts nothing once
                    // the call ended, and `end(with:)` resumes the caller.
                    if open {
                        start(self)
                    } else {
                        deliverIfEnded()
                    }
                }
            } onCancel: {
                end(with: Self.cancelledOutcome)
            }
        }

        /// End the call with `outcome`, unless the call already ended. The
        /// caller resumes now, or when the running `issue(_:)` body returns.
        func end(with outcome: Result<Data, AttestationError>) {
            end { outcome }
        }

        /// End the call with the outcome `body` returns, unless the call
        /// already ended. `body` runs only when this end is the first, so
        /// a key-state write inside it (the attestation record, or a
        /// discarded key ID) happens only for the answer that ends the call.
        /// Every other end that arrives while `body` runs does nothing, and
        /// the caller resumes after `body` returned, so the next serialized
        /// call reads what `body` wrote. `body` runs outside the lock.
        func end(_ body: () -> Result<Data, AttestationError>) {
            let won: Bool = state.withLock { state in
                guard state.isOpen else {
                    return false
                }
                state.closing = true
                return true
            }
            guard won else {
                return
            }
            let outcome = body()
            let delivery: Delivery? = state.withLock { state in
                state.outcome = outcome
                return state.takeDelivery()
            }
            delivery?.perform()
        }

        /// Run `body`, which stores a key ID or hands App Attest a method,
        /// while the call is open. Once the call ended, `body` does not run.
        /// An `end(with:)` that arrives while `body` runs takes effect when
        /// `body` returns. `body` runs outside the lock, so a completion
        /// handler that answers inside `body` ends the call without taking the
        /// lock twice.
        func issue(_ body: () -> Void) {
            let open: Bool = state.withLock { state in
                guard state.isOpen else {
                    return false
                }
                state.issuing += 1
                return true
            }
            guard open else {
                return
            }
            body()
            let delivery: Delivery? = state.withLock { state in
                state.issuing -= 1
                return state.takeDelivery()
            }
            delivery?.perform()
        }

        /// Resume the caller when the call ended and the caller has not
        /// received its outcome.
        private func deliverIfEnded() {
            let delivery: Delivery? = state.withLock { $0.takeDelivery() }
            delivery?.perform()
        }
    }

#endif // os(iOS) || os(macOS)
