#if os(iOS) || os(macOS)

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
        /// The platform App Attest service returned an error other than
        /// `DCError.featureUnsupported`, or the caller's task was cancelled
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
        /// generated a key; call `attest` first.
        case keyNotFound
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
        /// gives the timed-out call later: that answer stores no key ID and
        /// reaches no caller.
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
    /// The adapter hashes nothing. When App Attest is supported, it rejects a
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
    /// no key ID is stored, then `attestKey`) or one `assertRequest`
    /// (`generateAssertion`). It ends at the first of four events: an
    /// `assertRequest` that reads no stored key ID ends its call at that
    /// read with `SCP-ATTEST-9020` and calls no App Attest method; Apple's
    /// answers end it (an error from any of its App Attest methods, or the
    /// answer to its last one); `appAttestCallTimeLimit` (25 seconds from
    /// the call's start) passes; or the caller's task is cancelled. On the
    /// time limit the caller gets `SCP-ATTEST-9027`; on
    /// cancellation it gets `SCP-ATTEST-9001`, through
    /// `AttestationError.serviceError`. Either way the serializer runs the
    /// next queued call, and a completion handler Apple runs after the call
    /// ended stores no key ID, starts no further App Attest call, and reaches
    /// no caller. An end that arrives while the adapter stores a key ID or
    /// hands App Attest a method takes effect when that step returns, so a
    /// call never starts an App Attest method after it ended. A caller
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
    /// holds the key ID, not to one instance: `AppAttestKeyStateGuard`
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
        ///   `AttestationError.invalidClientDataHash`, `SCP-ATTEST-9001` for
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
        ///   `AttestationError.keyNotFound`, `SCP-ATTEST-9001` for
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
        /// 2. Retrieves or generates the App Attest key ID.
        /// 3. Calls `DCAppAttestService.attestKey(_:clientDataHash:)` with
        ///    `challenge` as `clientDataHash`, unchanged.
        /// 4. Returns the raw CBOR attestation object Apple signed.
        ///
        /// ADR-025 acceptance criterion 3 has the Rust core pass the binding
        /// digest `D` of `09-security-model.md` §9.3.1 as `challenge`. This
        /// adapter does not read `deviceId`, because `D` already binds the
        /// identity.
        ///
        /// When `DCAppAttestService.isSupported` is `false`, as on simulator,
        /// this method throws `AttestationError.unsupported`, calls no App
        /// Attest method, and returns no bytes. When `generateKey` or
        /// `attestKey` answers with `DCError.featureUnsupported`, it throws the
        /// same error after that call, and returns no bytes.
        ///
        /// - Parameters:
        ///   - challenge: The 32-byte §9.3.1 binding digest `D`.
        ///   - deviceId: Not read by this adapter.
        /// - Returns: The raw CBOR attestation object Apple signed.
        /// - Throws: `AttestationError.unsupported` when
        ///   `DCAppAttestService.isSupported` is `false`, or when `generateKey`
        ///   or `attestKey` answers with `DCError.featureUnsupported`.
        ///   `AttestationError.invalidClientDataHash` when App Attest is supported
        ///   and `challenge` is not 32 bytes; this method then generates no
        ///   key and calls no App Attest method.
        ///   `AttestationError.serviceError` when `generateKey` or `attestKey`
        ///   answers with any other error, or when the caller's task is
        ///   cancelled while the call is queued or outstanding.
        ///   `AttestationError.internalError` when `generateKey` or `attestKey`
        ///   answers with neither a value nor an error.
        ///   `AttestationError.timedOut` when `generateKey` and `attestKey`
        ///   together take longer than `appAttestCallTimeLimit`.
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
                    requestAttestation(keyId: keyId, challenge: challenge, call: call)
                    return
                }
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
        ///   no `attest` call has generated a key.
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
                service.generateAssertion(keyId, clientDataHash: requestHash) { assertion, error in
                    if let error {
                        call.end(with: .failure(.fromAppAttest(error, call: "generateAssertion")))
                    } else if let assertion {
                        call.end(with: .success(assertion))
                    } else {
                        call.end(with: .failure(.internalError("generateAssertion returned neither assertion nor error")))
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
        private func requestAttestation(keyId: String, challenge: Data, call: AppAttestCall) {
            service.attestKey(keyId, clientDataHash: challenge) { attestation, error in
                if let error {
                    call.end(with: .failure(.fromAppAttest(error, call: "attestKey")))
                } else if let attestation {
                    call.end(with: .success(attestation))
                } else {
                    call.end(with: .failure(.internalError("attestKey returned neither attestation nor error")))
                }
            }
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
    /// call ends at the first of an `assertRequest`'s read that finds no
    /// stored key ID, Apple's answer, `timeLimit`, or the caller's
    /// cancellation, and the serializer then starts the next queued call.
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
        /// `assertRequest` that reads no stored key ID), Apple's answer,
        /// `timeLimit`, or the caller's cancellation.
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
        /// when its caller is cancelled first.
        private func admit(_ ticket: UInt64) async -> Bool {
            if Task.isCancelled {
                return false
            }
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
    /// A key-ID read that finds no stored key ID in `assertRequest`, Apple's
    /// answer, the time limit and the caller's cancellation each try to end
    /// the call; the first one ends it, and each later one does nothing. The adapter stores a key ID and hands App Attest a method only
    /// inside `issue(_:)`, which runs nothing once the call ended. An end that
    /// arrives while an `issue(_:)` body runs takes effect, and resumes the
    /// caller, when that body returns, so every key ID a call stores and every
    /// App Attest method it starts comes before the call ends.
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
            /// The outcome the first `end(with:)` set; `nil` while the call
            /// is open.
            var outcome: Result<Data, AttestationError>?
            /// Whether the caller has received `outcome`.
            var delivered = false
            /// The number of `issue(_:)` bodies running.
            var issuing = 0
            var waiter: CheckedContinuation<Result<Data, AttestationError>, Never>?
            var timer: Task<Void, Never>?

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
                        guard state.outcome == nil else {
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
                    // A call that ended before the lock above, or between
                    // that lock and `issue`, starts nothing; its caller
                    // receives the outcome here or from `end(with:)`.
                    if !open || !issue({ start(self) }) {
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
            let delivery: Delivery? = state.withLock { state in
                guard state.outcome == nil else {
                    return nil
                }
                state.outcome = outcome
                return state.takeDelivery()
            }
            delivery?.perform()
        }

        /// Run `body`, which stores a key ID or hands App Attest a method,
        /// while the call is open, and report whether it ran. Once the call
        /// ended, `body` does not run. An `end(with:)` that arrives while
        /// `body` runs takes effect when `body` returns. `body` runs outside
        /// the lock, so a completion handler that answers inside `body` ends
        /// the call without taking the lock twice.
        @discardableResult
        func issue(_ body: () -> Void) -> Bool {
            let open: Bool = state.withLock { state in
                guard state.outcome == nil else {
                    return false
                }
                state.issuing += 1
                return true
            }
            guard open else {
                return false
            }
            body()
            let delivery: Delivery? = state.withLock { state in
                state.issuing -= 1
                return state.takeDelivery()
            }
            delivery?.perform()
            return true
        }

        /// Resume the caller when the call ended and the caller has not
        /// received its outcome.
        private func deliverIfEnded() {
            let delivery: Delivery? = state.withLock { $0.takeDelivery() }
            delivery?.perform()
        }
    }

#endif // os(iOS) || os(macOS)
