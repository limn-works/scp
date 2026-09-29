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
    /// `AppleDeviceAttestation` is `final` and conforms to `Sendable`. Internal
    /// mutable state (`generationTask`, `UserDefaults`) is protected by `NSLock`.
    /// `attestKey` and `generateAssertion` bridge to structured concurrency
    /// through `withCheckedContinuation` and return Apple's answer as a
    /// `Result`; `generateKey` bridges through
    /// `withCheckedThrowingContinuation`.
    ///
    /// See ADR-025 and the UniFFI `DeviceAttestationProvider` callback
    /// interface in `crates/scp-ffi/uniffi/src/lib.rs`, which this class
    /// conforms to.
    public final class AppleDeviceAttestation: DeviceAttestationProvider, @unchecked Sendable {
        // `@unchecked Sendable` is required because this class conforms to the
        // UniFFI `DeviceAttestationProvider` callback interface, whose Rust trait
        // requires `Send + Sync` (Rust) → `Sendable` (Swift). No Rust code holds or
        // calls that callback yet, so nothing injects this class into the Rust engine. Internal mutable
        // state (`generationTask`, `UserDefaults`) is protected by `lock`; no reference
        // semantics escape across the FFI boundary. This is the same exception as
        // `MessageListenerAdapter`. See .docs/standards/swift.md §Sendable — UniFFI exception.

        private let service: DCAppAttestService
        private let defaults: UserDefaults
        private let lock: NSLock
        private var generationTask: Task<String, Error>?

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
            lock = NSLock()
        }

        /// Testing initializer that accepts injected dependencies.
        ///
        /// Used in unit tests to supply a mock `DCAppAttestService` subclass and
        /// an in-memory `UserDefaults` suite.
        init(service: DCAppAttestService, defaults: UserDefaults) {
            self.service = service
            self.defaults = defaults
            lock = NSLock()
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

            let keyId: String
            do {
                keyId = try await resolveKeyId()
            } catch let error as AttestationError {
                throw error
            } catch {
                throw AttestationError.serviceError(error.localizedDescription)
            }

            let outcome: Result<Data, AttestationError> = await withCheckedContinuation { continuation in
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

            guard let keyId = loadKeyId() else {
                throw AttestationError.keyNotFound
            }

            let outcome: Result<Data, AttestationError> = await withCheckedContinuation { continuation in
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
            return try outcome.get()
        }

        // MARK: - Private helpers

        /// Retrieve the stored App Attest key ID, or generate and store a new one.
        ///
        /// Uses a task-coalescing pattern to prevent TOCTOU races: if concurrent
        /// callers both find no key in `UserDefaults`, only one key generation
        /// task is started; all callers await the same task result. This prevents
        /// multiple Secure Enclave keys from being generated on concurrent first
        /// calls to `attest(challenge:deviceId:)`.
        ///
        /// - Returns: An App Attest key ID string suitable for use in
        ///   `attestKey(_:clientDataHash:)` and `generateAssertion(_:clientDataHash:)`.
        /// - Throws: `AttestationError.unsupported` if `generateKey` answers
        ///   `DCError.featureUnsupported`, `AttestationError.serviceError` if it
        ///   answers any other error.
        private func resolveKeyId() async throws -> String {
            // Phase 1: synchronous check under lock. Returns either the existing
            // key ID string, an in-flight Task to await, or nil meaning we must
            // start a new task.
            enum Outcome {
                case existing(String)
                case coalesce(Task<String, Error>)
                case startNew
            }
            let outcome: Outcome = lock.withLock {
                if let existing = defaults.string(forKey: StorageKey.appAttestKeyId) {
                    return .existing(existing)
                }
                if let ongoing = generationTask {
                    return .coalesce(ongoing)
                }
                return .startNew
            }

            switch outcome {
            case let .existing(keyId):
                return keyId
            case let .coalesce(task):
                return try await task.value
            case .startNew:
                // The caller's frame holds `self` across `await task.value`, so
                // a strong capture keeps no reference alive past that await.
                let task = Task<String, Error> {
                    try await self.generateAndStoreKey()
                }
                lock.withLock { generationTask = task }
                defer { lock.withLock { generationTask = nil } }
                return try await task.value
            }
        }

        /// Generate a new App Attest key and persist its ID.
        ///
        /// Wraps `DCAppAttestService.generateKey(completionHandler:)` via
        /// `withCheckedThrowingContinuation` to produce an `async` function.
        ///
        /// - Returns: The newly generated App Attest key ID.
        /// - Throws: `AttestationError.unsupported` if the service call answers
        ///   `DCError.featureUnsupported`, `AttestationError.serviceError` if it
        ///   answers any other error.
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

#endif // os(iOS) || os(macOS)
