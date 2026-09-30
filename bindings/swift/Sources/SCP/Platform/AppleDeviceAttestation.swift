#if os(iOS) || os(macOS)

    import DeviceCheck
    import Foundation

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
        /// `DCError.featureUnsupported`.
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
    /// stored key ID after every preceding call finished writing it, and
    /// concurrent `attest` calls on a device with no stored key generate one
    /// key. `attest` and
    /// `assertRequest` check `isSupported` and the 32-byte length before they
    /// queue a call, so a call either check rejects waits for no other call.
    /// `attestKey` and `generateAssertion` bridge to structured concurrency
    /// through `withCheckedContinuation` and return Apple's answer as a
    /// `Result`; `generateKey` bridges through
    /// `withCheckedThrowingContinuation`.
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
        /// key ID after every preceding call finished writing it, and
        /// concurrent `attest` calls generate one key.
        private let callSerializer: AppAttestCallSerializer

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
            let keyStateGuard = AppAttestKeyStateGuard.guarding(defaults)
            lock = keyStateGuard.lock
            callSerializer = keyStateGuard.callSerializer
        }

        /// Testing initializer that accepts injected dependencies.
        ///
        /// Used in unit tests to supply a mock `DCAppAttestService` subclass and
        /// an in-memory `UserDefaults` suite. Every adapter built over one
        /// `defaults` object shares one lock and one serializer, as every
        /// adapter `init()` builds does.
        init(service: DCAppAttestService, defaults: UserDefaults) {
            self.service = service
            self.defaults = defaults
            let keyStateGuard = AppAttestKeyStateGuard.guarding(defaults)
            lock = keyStateGuard.lock
            callSerializer = keyStateGuard.callSerializer
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
        ///   `AttestationError.serviceError`, or `SCP-ATTEST-9025` for
        ///   `AttestationError.internalError`, in the cases
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
        ///   `AttestationError.serviceError`, or `SCP-ATTEST-9025` for
        ///   `AttestationError.internalError`, in the cases
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
        ///   answers with any other error.
        ///   `AttestationError.internalError` when `generateKey` or `attestKey`
        ///   answers with neither a value nor an error.
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
            // the serialized body, so it follows every write a preceding call
            // made, and concurrent first calls generate one key.
            let outcome = await callSerializer.run { [self] () -> Result<Data, AttestationError> in
                let keyId: String
                do {
                    keyId = try await resolveKeyId()
                } catch let error as AttestationError {
                    return .failure(error)
                } catch {
                    return .failure(.serviceError(error.localizedDescription))
                }

                return await withCheckedContinuation { continuation in
                    service.attestKey(keyId, clientDataHash: challenge) { attestation, error in
                        if let error {
                            continuation.resume(returning: .failure(.fromAppAttest(error, call: "attestKey")))
                        } else if let attestation {
                            continuation.resume(returning: .success(attestation))
                        } else {
                            continuation.resume(returning: .failure(.internalError(
                                "attestKey returned neither attestation nor error"
                            )))
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
        ///   no `attest` call has generated a key.
        ///   `AttestationError.serviceError` when `generateAssertion` answers
        ///   with any other error.
        ///   `AttestationError.internalError` when `generateAssertion` answers
        ///   with neither an assertion nor an error.
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

            // The key ID is read inside the serialized body for the reason
            // `attestReportingAttestationError(challenge:deviceId:)` states.
            let outcome = await callSerializer.run { [self] () -> Result<Data, AttestationError> in
                guard let keyId = loadKeyId() else {
                    return .failure(.keyNotFound)
                }

                return await withCheckedContinuation { continuation in
                    service.generateAssertion(keyId, clientDataHash: requestHash) { assertion, error in
                        if let error {
                            continuation.resume(returning: .failure(.fromAppAttest(error, call: "generateAssertion")))
                        } else if let assertion {
                            continuation.resume(returning: .success(assertion))
                        } else {
                            continuation.resume(returning: .failure(.internalError(
                                "generateAssertion returned neither assertion nor error"
                            )))
                        }
                    }
                }
            }
            return try outcome.get()
        }

        // MARK: - Private helpers

        /// Retrieve the stored App Attest key ID, or generate and store a new one.
        ///
        /// A caller reaches this method through `callSerializer`, which is what
        /// makes concurrent callers that find no stored key ID generate one key
        /// rather than one each: the second caller reads the key ID only after
        /// the first caller stored it. `loadKeyId()` reads `UserDefaults` under
        /// `lock` on every call, and this adapter caches no key ID.
        ///
        /// - Returns: An App Attest key ID string suitable for use in
        ///   `attestKey(_:clientDataHash:)` and `generateAssertion(_:clientDataHash:)`.
        /// - Throws: `AttestationError.unsupported` if `generateKey` answers
        ///   `DCError.featureUnsupported`, `AttestationError.serviceError` if it
        ///   answers any other error, `AttestationError.internalError` if it
        ///   answers neither a key ID nor an error.
        private func resolveKeyId() async throws -> String {
            if let stored = loadKeyId() {
                return stored
            }
            return try await generateAndStoreKey()
        }

        /// Generate a new App Attest key and persist its ID.
        ///
        /// Wraps `DCAppAttestService.generateKey(completionHandler:)` via
        /// `withCheckedThrowingContinuation` to produce an `async` function.
        ///
        /// - Returns: The newly generated App Attest key ID.
        /// - Throws: `AttestationError.unsupported` if the service call answers
        ///   `DCError.featureUnsupported`, `AttestationError.serviceError` if it
        ///   answers any other error, `AttestationError.internalError` if it
        ///   answers neither a key ID nor an error.
        private func generateAndStoreKey() async throws -> String {
            let keyId: String = try await withCheckedThrowingContinuation { continuation in
                service.generateKey { keyId, error in
                    if let error {
                        continuation.resume(throwing: AttestationError.fromAppAttest(error, call: "generateKey"))
                    } else if let keyId {
                        continuation.resume(returning: keyId)
                    } else {
                        continuation.resume(throwing: AttestationError.internalError(
                            "generateKey returned neither keyId nor error"
                        ))
                    }
                }
            }
            storeKeyId(keyId)
            return keyId
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
    /// `run(_:)` job. Swift's default actor executor does not promise to run
    /// jobs in the order callers made them: it may run a later,
    /// higher-priority caller's job before an earlier, lower-priority one. So
    /// the order App Attest sees is the acceptance order, not the order in
    /// which callers called `attest` or `assertRequest`. Mutual exclusion and
    /// the one-key guarantee do not depend on that order.
    ///
    /// **Why serialization, rather than a lock around the key-ID read:**
    /// `generateKey` answers through a completion handler, so a lock cannot be
    /// held from the read that finds no stored key ID to the write that stores
    /// the generated one. Two first `attest` calls that each held the lock only
    /// for the read would both find no key ID and generate one key each.
    /// Running each call's whole body, from the key-ID read through Apple's
    /// answer, before the next body starts makes each read follow every
    /// preceding call's write.
    ///
    /// `run(_:)` chains each caller's work onto whatever work this serializer
    /// last accepted, and it publishes that chaining inside actor isolation, so
    /// two callers that arrive together take distinct positions in one order
    /// rather than both reading an empty tail.
    private actor AppAttestCallSerializer {
        /// Work this serializer last accepted, which the next caller waits for.
        private var tail: Task<Void, Never>?

        /// Run `body` after every call this serializer already accepted, and
        /// return what `body` returned.
        ///
        /// - Parameter body: One App Attest call, together with the key-ID
        ///   read and write it makes.
        func run<Outcome: Sendable>(_ body: @Sendable @escaping () async -> Outcome) async -> Outcome {
            let predecessor = tail
            let work = Task<Outcome, Never> {
                await predecessor?.value
                return await body()
            }
            tail = Task { _ = await work.value }
            return await work.value
        }
    }

#endif // os(iOS) || os(macOS)
