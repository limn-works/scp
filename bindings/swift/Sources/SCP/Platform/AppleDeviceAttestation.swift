#if os(iOS) || os(macOS)

    import CryptoKit
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
        /// The platform App Attest service returned an error.
        case serviceError(String)
        /// `DCAppAttestService` reports `isSupported == false`, so this device
        /// cannot produce an App Attest attestation or assertion.
        ///
        /// A caller catches this case to learn that the device holds no
        /// hardware attestation signal. §9.3 of the security model spec,
        /// "Sybil resistance and identity uniqueness", states that the absence
        /// of a device attestation is expected and is not penalizing, so the
        /// caller presents no attestation rather than presenting a weaker one.
        case unsupported(String)
        /// The stored App Attest key ID is missing; call `attest` first.
        case keyNotFound
        /// Apple answered `attestKey` with `DCError.invalidKey` for a key this
        /// adapter already attested.
        ///
        /// `DCError.h` lists "you call `attestKey:clientDataHash:` for a key
        /// that's already been attested" as one cause of that code. Apple
        /// attests one key once, so a caller that holds an attestation already
        /// calls `assertRequest(requestHash:)` for every later request instead
        /// of calling `attest` again. This adapter keeps that key.
        case keyAlreadyAttested(String)
        /// Apple answered `generateAssertion` with `DCError.invalidKey` for a
        /// key this adapter generated and never attested.
        ///
        /// `DCError.h` lists "you call `generateAssertion:clientDataHash:` with
        /// an unattested key" as one cause of that code. A caller reaches this
        /// state when an earlier `attest` failed after key generation, so it
        /// calls `attest(challenge:deviceId:)` before asserting again. This
        /// adapter keeps that key.
        case keyNotAttested(String)
        /// Apple's App Attest service rejected this device's key, so this
        /// adapter discarded its key ID.
        ///
        /// `DCError.h` lists "the App Attest service rejects the key" as one
        /// cause of `DCError.invalidKey`. A later `attest(challenge:deviceId:)`
        /// generates a replacement key.
        case keyRejected(String)
        /// Apple could not reach its App Attest service during an attestation.
        ///
        /// `DCError.h` instructs a caller to "try the attestation again later
        /// using the same key and the same value for the `clientDataHash`
        /// parameter", because "retrying with the same inputs helps to preserve
        /// the risk metric for a given device". This adapter keeps that key, so
        /// a retry reaches Apple with a key Apple already saw.
        case serverUnavailable(String)
        /// An internal invariant was violated.
        case internalError(String)
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
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Storage key constants
    // ---------------------------------------------------------------------------

    private enum StorageKey {
        /// `UserDefaults` key under which the App Attest key ID is persisted.
        static let appAttestKeyId = "dev.limn.scp.appAttest.keyId"

        /// `UserDefaults` key under which a key ID Apple attested is persisted.
        ///
        /// Apple returns one error code, `DCError.invalidKey`, for three
        /// different conditions, and which condition holds depends on whether a
        /// key was attested. Recording a successful attestation is what lets
        /// this adapter tell those conditions apart. This key holds a key ID
        /// rather than a flag, so a stale value cannot describe a key ID that
        /// replaced it.
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
    ///
    /// Attestation steps (per ADR-025 §"Device attestation"):
    /// 1. `generateKey` — creates a Secure Enclave key via App Attest service.
    /// 2. `attestKey(_:clientDataHash:)` — requests Apple's attestation object
    ///    where `clientDataHash = SHA-256(clientDataJSON)`.
    /// 3. `generateAssertion(_:clientDataHash:)` — per-request proof of possession.
    ///
    /// ## Unavailable service (simulator, or a device without App Attest)
    ///
    /// When `DCAppAttestService.isSupported` is `false`, `attest` and
    /// `assertRequest` throw `ScpError.Identity` with code `SCP-ATTEST-9019`,
    /// which `AttestationError.unsupported` maps to. The adapter mints
    /// no substitute token, because a locally fabricated token would assert a
    /// hardware guarantee that no hardware produced. §9.3 of the security model
    /// spec, "Sybil resistance and identity uniqueness", states that the
    /// absence of a device attestation is expected and is not penalizing, so
    /// the honest result is the typed error rather than a token.
    ///
    /// A caller that wants to branch before it calls reads `isHardwareBacked`.
    ///
    /// ## Thread safety
    ///
    /// `AppleDeviceAttestation` is `final` and conforms to `Sendable`. Internal
    /// mutable state (`generationTask`, `UserDefaults`) is protected by `NSLock`.
    /// All async methods use `withCheckedThrowingContinuation` to bridge the
    /// completion-handler APIs to structured concurrency.
    ///
    /// See ADR-025 and `crates/scp-platform/src/traits.rs` `DeviceAttestation`.
    public final class AppleDeviceAttestation: DeviceAttestationProvider, @unchecked Sendable {
        // `@unchecked Sendable` is required because this class is injected into the
        // Rust engine via the UniFFI `DeviceAttestationProvider` callback interface,
        // which requires `Send + Sync` (Rust) → `Sendable` (Swift). Internal mutable
        // state (`generationTask`, `UserDefaults`) is protected by `lock`; no reference
        // semantics escape across the FFI boundary. This is the same exception as
        // `MessageListenerAdapter`. See .docs/standards/swift.md §Sendable — UniFFI exception.

        private let service: DCAppAttestService
        private let defaults: UserDefaults
        private let lock: NSLock
        private var generationTask: Task<String, Error>?

        /// Runs one App Attest call at a time, so `classify(_:keyId:operation:)`
        /// reads an attestation record no other call is concurrently writing,
        /// and each call reads the stored key ID after every preceding call
        /// finished writing it.
        private let callSerializer: AppAttestCallSerializer

        /// Whether this instance is running in hardware-backed mode.
        ///
        /// `false` on simulator or devices where App Attest is unavailable.
        public var isHardwareBacked: Bool {
            service.isSupported
        }

        // MARK: - Init

        /// Creates an `AppleDeviceAttestation` using the shared
        /// `DCAppAttestService`.
        ///
        /// No I/O is performed during initialization; key generation is deferred
        /// to the first call to `attest(challenge:deviceId:)`.
        ///
        public init() {
            service = DCAppAttestService.shared
            defaults = UserDefaults.standard
            lock = NSLock()
            callSerializer = AppAttestCallSerializer()
        }

        /// Testing initializer that accepts injected dependencies.
        ///
        /// Used in unit tests to supply a mock `DCAppAttestService` subclass and
        /// an in-memory `UserDefaults` suite.
        init(service: DCAppAttestService, defaults: UserDefaults) {
            self.service = service
            self.defaults = defaults
            lock = NSLock()
            callSerializer = AppAttestCallSerializer()
        }

        // MARK: - DeviceAttestationProvider

        /// The `DeviceAttestationProvider` callback method Rust calls through
        /// UniFFI to obtain an attestation.
        ///
        /// The UniFFI callback declares `ScpError` as its error type. The
        /// generated glue lowers a thrown `ScpError` into an error value that
        /// Rust receives, and hands any other thrown type to Rust as an
        /// unexpected callback error, which panics on the Rust side. This
        /// method therefore throws `ScpError` only: it translates each
        /// `AttestationError` through `AttestationError.scpError`, and
        /// `attestReportingAttestationError(challenge:deviceId:)` declares
        /// `throws(AttestationError)`, so the compiler rejects any other type.
        public func attest(challenge: Data, deviceId: Data) async throws(ScpError) -> Data {
            do throws(AttestationError) {
                return try await attestReportingAttestationError(challenge: challenge, deviceId: deviceId)
            } catch {
                throw error.scpError
            }
        }

        /// The `DeviceAttestationProvider` callback method Rust calls through
        /// UniFFI to obtain an assertion. It throws `ScpError` only, for the
        /// reason `attest(challenge:deviceId:)` states.
        public func assertRequest(requestHash: Data) async throws(ScpError) -> Data {
            do throws(AttestationError) {
                return try await assertRequestReportingAttestationError(requestHash: requestHash)
            } catch {
                throw error.scpError
            }
        }

        /// Generate an attestation token for the given challenge and device ID.
        ///
        /// On a real device with App Attest available:
        /// 1. Retrieves or generates the App Attest key ID.
        /// 2. Computes `clientDataHash = SHA-256(clientDataJSON)` where
        ///    `clientDataJSON = {"challenge":"<b64>","deviceId":"<b64>","type":"scp-device-attestation-v1"}`.
        /// 3. Calls `DCAppAttestService.attestKey(_:clientDataHash:)`.
        /// 4. Returns the raw CBOR attestation bytes.
        ///
        /// On simulator or on a device where App Attest is unavailable, this
        /// method throws `AttestationError.unsupported` and returns no bytes.
        ///
        /// - Parameters:
        ///   - challenge: Server-issued random challenge bytes.
        ///   - deviceId: Stable device/identity identifier bytes.
        /// - Returns: Raw CBOR attestation-object bytes that Apple signed.
        /// - Throws: `AttestationError.unsupported` when
        ///   `DCAppAttestService.isSupported` is `false`.
        ///   `AttestationError.keyAlreadyAttested` when Apple already attested
        ///   this device's key, which makes `assertRequest(requestHash:)` a
        ///   caller's next call.
        ///   `AttestationError.keyRejected` when Apple's App Attest service
        ///   rejected this device's key; this method discards its key ID, so a
        ///   later call generates a replacement.
        ///   `AttestationError.serverUnavailable` when Apple could not reach its
        ///   App Attest service; this method keeps that key, so a retry reaches
        ///   Apple with a key Apple already saw.
        ///   `AttestationError.serviceError` for every other App Attest error.
        ///   `classify(_:keyId:operation:)` states which condition each
        ///   `DCError.invalidKey` maps to.
        func attestReportingAttestationError(
            challenge: Data,
            deviceId: Data
        ) async throws(AttestationError) -> Data {
            guard service.isSupported else {
                throw AttestationError.unsupported(
                    "DCAppAttestService.isSupported is false on this device, so App Attest cannot "
                        + "produce an attestation. This adapter mints no substitute token."
                )
            }

            let clientDataHash = computeClientDataHash(challenge: challenge, deviceId: deviceId)

            // The key ID is read inside the serialized body, because a call
            // queued behind a predecessor that discarded or replaced the key
            // would otherwise reach Apple with a key ID this adapter no longer
            // stores, and `classify(_:keyId:operation:)` would then name a
            // condition that does not hold.
            let outcome = await callSerializer.run { [weak self] () -> Result<Data, AttestationError> in
                guard let self else { return .failure(.internalError("self was deallocated")) }
                let keyId: String
                do {
                    keyId = try await self.resolveKeyId()
                } catch let error as AttestationError {
                    return .failure(error)
                } catch {
                    return .failure(.serviceError(error.localizedDescription))
                }
                return await self.requestAttestation(keyId: keyId, clientDataHash: clientDataHash)
            }
            return try outcome.get()
        }

        /// Call `attestKey(_:clientDataHash:)` once and translate its answer.
        ///
        /// A caller reaches this method through `callSerializer`, which is what
        /// keeps `classify(_:keyId:operation:)` from reading an attestation
        /// record that another App Attest call is concurrently writing.
        private func requestAttestation(
            keyId: String,
            clientDataHash: Data
        ) async -> Result<Data, AttestationError> {
            await withCheckedContinuation { continuation in
                service.attestKey(keyId, clientDataHash: clientDataHash) { [weak self] attestation, error in
                    if let error {
                        guard let self else {
                            continuation.resume(returning: .failure(.internalError("self was deallocated")))
                            return
                        }
                        continuation.resume(returning: .failure(self.classify(
                            error,
                            keyId: keyId,
                            operation: .attestation
                        )))
                    } else if let attestation {
                        // Apple attests one key once, so recording which key it
                        // attested is what tells a later `DCError.invalidKey`
                        // from `attestKey` apart from a rejected key. This write
                        // precedes this continuation's resume, and a serialized
                        // successor starts only after that resume, so a
                        // successor's `classify` reads this write.
                        self?.markKeyAttested(keyId)
                        continuation.resume(returning: .success(attestation))
                    } else {
                        continuation.resume(returning: .failure(.internalError(
                            "attestKey returned neither attestation nor error"
                        )))
                    }
                }
            }
        }

        /// Generate a per-request assertion for a previously attested key.
        ///
        /// On a real device with App Attest available, calls
        /// `DCAppAttestService.generateAssertion(_:clientDataHash:)` and passes
        /// `requestHash` as `clientDataHash` unchanged. The assertion binds the
        /// request hash to the stored App Attest key.
        ///
        /// On simulator or on a device where App Attest is unavailable, this
        /// method throws `AttestationError.unsupported` and returns no bytes.
        ///
        /// - Parameter requestHash: SHA-256 digest of the request payload.
        /// - Returns: Assertion bytes to include in the relay request.
        /// - Throws: `AttestationError.unsupported` when
        ///   `DCAppAttestService.isSupported` is `false`.
        ///   `AttestationError.keyNotFound` when no key ID is stored, which
        ///   happens when no caller has called `attest` yet.
        ///   `AttestationError.keyNotAttested` when a key ID is stored and Apple
        ///   attested no key, which makes `attest(challenge:deviceId:)` a
        ///   caller's next call; this method keeps that key.
        ///   `AttestationError.keyRejected` when Apple's App Attest service
        ///   rejected an attested key; this method discards its key ID.
        ///   `AttestationError.serviceError` for every other App Attest error.
        func assertRequestReportingAttestationError(
            requestHash: Data
        ) async throws(AttestationError) -> Data {
            guard service.isSupported else {
                throw AttestationError.unsupported(
                    "DCAppAttestService.isSupported is false on this device, so App Attest cannot "
                        + "produce an assertion. This adapter mints no substitute token."
                )
            }

            // The key ID is read inside the serialized body for the reason
            // `attest(challenge:deviceId:)` states.
            let outcome = await callSerializer.run { [weak self] () -> Result<Data, AttestationError> in
                guard let self else { return .failure(.internalError("self was deallocated")) }
                guard let keyId = self.loadKeyId() else { return .failure(.keyNotFound) }
                return await self.requestAssertion(keyId: keyId, requestHash: requestHash)
            }
            return try outcome.get()
        }

        /// Call `generateAssertion(_:clientDataHash:)` once and translate its
        /// answer.
        ///
        /// A caller reaches this method through `callSerializer`, which is what
        /// keeps `classify(_:keyId:operation:)` from reading an attestation
        /// record that another App Attest call is concurrently writing.
        private func requestAssertion(
            keyId: String,
            requestHash: Data
        ) async -> Result<Data, AttestationError> {
            await withCheckedContinuation { continuation in
                service.generateAssertion(keyId, clientDataHash: requestHash) { [weak self] assertion, error in
                    if let error {
                        guard let self else {
                            continuation.resume(returning: .failure(.internalError("self was deallocated")))
                            return
                        }
                        continuation.resume(returning: .failure(self.classify(
                            error,
                            keyId: keyId,
                            operation: .assertion
                        )))
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

        // MARK: - App Attest error classification

        /// Which App Attest call produced an error.
        ///
        /// Apple returns `DCError.invalidKey` for three different conditions,
        /// and which call raised it narrows those three to two.
        private enum AppAttestOperation {
            case attestation
            case assertion
        }

        /// Translate an App Attest service error into a typed error, and update
        /// stored key state when that error says a key is gone.
        ///
        /// **Criterion this method applies**, quoting `DCError.h` word for word.
        /// `DCErrorInvalidKey` is "an error caused by a failed attempt to use
        /// the App Attest key. You receive this error if something goes wrong
        /// with generating, retrieving, or using an App Attest cryptographic
        /// key, when: you call `attestKey:clientDataHash:completionHandler:`
        /// for a key that's already been attested; you call
        /// `generateAssertion:clientDataHash:completionHandler:` with an
        /// unattested key; the App Attest service rejects the key."
        ///
        /// Which call raised that code, together with whether this adapter
        /// recorded an attestation for `keyId`, separates those three:
        ///
        /// | Call | Attested | Condition | Key |
        /// | --- | --- | --- | --- |
        /// | `attestKey` | yes | already attested | kept |
        /// | `attestKey` | no | service rejected it | discarded |
        /// | `generateAssertion` | no | unattested key | kept |
        /// | `generateAssertion` | yes | service rejected it | discarded |
        ///
        /// **What makes an attestation record a sound input.** This table reads
        /// a record `markKeyAttested(_:)` writes when `attestKey` succeeds, and
        /// that record describes the key App Attest holds only while no other
        /// App Attest call for that key is outstanding. Two concurrent
        /// `attest` calls without that guarantee lose a live key: one call
        /// succeeds and records an attestation, the other reads that record
        /// before the first wrote it, reads row `attestKey`/no, and discards a
        /// key Apple had just attested. `callSerializer` runs one App Attest
        /// call at a time, and each call reads the stored key ID inside its
        /// serialized body, so every read here, of the attestation record and
        /// of the key ID the call names, follows every write a preceding call
        /// made.
        ///
        /// **One ambiguity this table leaves standing.** A device restored from
        /// a backup can carry a recorded attestation for a key its Secure
        /// Enclave no longer holds, and `attestKey` then answers
        /// `DCError.invalidKey` for a rejected key while this table reads
        /// "already attested". This method keeps that key rather than
        /// discarding it, because discarding a live key costs a caller its
        /// attested key and its device risk metric, while keeping a dead key
        /// costs one failed call: a caller reaches `assertRequest`, whose
        /// attested-and-invalid row discards that key and lets a later `attest`
        /// generate a replacement.
        private func classify(
            _ error: Error,
            keyId: String,
            operation: AppAttestOperation
        ) -> AttestationError {
            guard let code = (error as? DCError)?.code else {
                return .serviceError(error.localizedDescription)
            }
            switch code {
            case .serverUnavailable:
                return .serverUnavailable(error.localizedDescription)
            case .invalidKey:
                switch (operation, isKeyAttested(keyId)) {
                case (.attestation, true):
                    return .keyAlreadyAttested(
                        "App Attest already attested this key, so ask it for an assertion rather "
                            + "than for a second attestation: \(error.localizedDescription)"
                    )
                case (.assertion, false):
                    return .keyNotAttested(
                        "App Attest holds no attestation for this key, so attest it before asking "
                            + "for an assertion: \(error.localizedDescription)"
                    )
                case (.attestation, false), (.assertion, true):
                    forgetKeyId(keyId)
                    return .keyRejected(
                        "App Attest rejected this device's key, and this adapter discarded its key "
                            + "ID, so a later attest generates a replacement: "
                            + error.localizedDescription
                    )
                }
            default:
                return .serviceError(error.localizedDescription)
            }
        }

        // MARK: - Private helpers

        /// Retrieve a stored App Attest key ID, or generate and store a new one.
        ///
        /// One critical section reads `UserDefaults`, reads `generationTask`,
        /// and — when both come up empty — creates a generation task and
        /// publishes it into `generationTask`. Publishing inside a critical
        /// section that observed absence is what makes concurrent callers
        /// coalesce: a second caller entering that section afterward reads a
        /// published task and awaits it, so `generateKey` runs once and this
        /// device holds one Secure Enclave App Attest key. Reading in one
        /// critical section and publishing in a second would let two callers
        /// each observe absence and each generate a key.
        ///
        /// - Returns: An App Attest key ID string suitable for use in
        ///   `attestKey(_:clientDataHash:)` and `generateAssertion(_:clientDataHash:)`.
        /// - Throws: `AttestationError.serviceError` if `generateKey` fails.
        private func resolveKeyId() async throws -> String {
            enum Outcome {
                /// A key ID `UserDefaults` already holds.
                case existing(String)
                /// A generation task another caller started and published.
                case coalesce(Task<String, Error>)
                /// A generation task this caller created and published, and
                /// this caller therefore clears when it finishes.
                case started(Task<String, Error>)
            }

            let outcome: Outcome = lock.withLock {
                if let existing = defaults.string(forKey: StorageKey.appAttestKeyId) {
                    return .existing(existing)
                }
                if let ongoing = generationTask {
                    return .coalesce(ongoing)
                }
                // Creating a `Task` schedules its body on a concurrent executor
                // and returns immediately, so that body waits for no part of
                // this critical section and takes `lock` only after `withLock`
                // releases it.
                let task = Task<String, Error> { [weak self] in
                    guard let self else { throw AttestationError.internalError("self was deallocated") }
                    return try await self.generateAndStoreKey()
                }
                generationTask = task
                return .started(task)
            }

            switch outcome {
            case let .existing(keyId):
                return keyId
            case let .coalesce(task):
                return try await task.value
            case let .started(task):
                // Clear only a task this caller published. Publishing happens
                // in one place, so `generationTask` holds either this task or
                // nothing when this runs; comparing identity keeps that true
                // for anyone who later adds a second publishing site.
                //
                // A caller arriving between a failed generation and this line
                // reads a published task that already threw, and receives that
                // same error instead of starting a fresh generation. That
                // window closes when this line runs, and a caller arriving
                // afterward starts a fresh generation.
                defer {
                    lock.withLock {
                        if generationTask == task {
                            generationTask = nil
                        }
                    }
                }
                return try await task.value
            }
        }

        /// Generate a new App Attest key and persist its ID.
        ///
        /// Wraps `DCAppAttestService.generateKey(completionHandler:)` via
        /// `withCheckedThrowingContinuation` to produce an `async` function.
        ///
        /// - Returns: The newly generated App Attest key ID.
        /// - Throws: `AttestationError.serviceError` if the service call fails.
        private func generateAndStoreKey() async throws -> String {
            let keyId: String = try await withCheckedThrowingContinuation { continuation in
                service.generateKey { keyId, error in
                    if let error {
                        continuation.resume(throwing: AttestationError.serviceError(error.localizedDescription))
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

        /// Compute the client data hash for App Attest.
        ///
        /// Uses structured JSON encoding to prevent length-confusion on naive byte
        /// concatenation. Per ADR-025 (updated): `clientDataHash = SHA256(clientDataJSON)`
        /// where `clientDataJSON = {"challenge":"<b64>","deviceId":"<b64>","type":"scp-device-attestation-v1"}`.
        /// Field order is fixed to ensure cross-platform determinism.
        ///
        /// A reader verifying the attestation reconstructs this JSON with the
        /// same fixed-field-order formula to check the nonce Apple embedded in
        /// the App Attest leaf certificate.
        private func computeClientDataHash(challenge: Data, deviceId: Data) -> Data {
            let json = "{\"challenge\":\"\(challenge.base64EncodedString())\",\"deviceId\":\"\(deviceId.base64EncodedString())\",\"type\":\"scp-device-attestation-v1\"}"
            return Data(SHA256.hash(data: Data(json.utf8)))
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
        /// A freshly generated key carries no attestation, so this method also
        /// removes any recorded attestation, which keeps a record left by a
        /// previous key from describing this one.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// - Parameter keyId: The key ID returned by
        ///   `DCAppAttestService.generateKey`.
        private func storeKeyId(_ keyId: String) {
            lock.lock()
            defer { lock.unlock() }
            defaults.set(keyId, forKey: StorageKey.appAttestKeyId)
            defaults.removeObject(forKey: StorageKey.attestedAppAttestKeyId)
        }

        /// Record that Apple attested `keyId`.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// - Parameter keyId: A key ID `attestKey` answered with an attestation.
        ///   Recording it only while it is still this adapter's stored key ID
        ///   keeps a concurrent regeneration's key ID from inheriting an
        ///   attestation Apple granted to a key it replaced.
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

        /// Remove a stored App Attest key ID and any attestation recorded for
        /// it, unless another key ID replaced it.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// - Parameter keyId: A key ID Apple's App Attest service rejected.
        ///   Removing only this value keeps a concurrent regeneration's key ID
        ///   in place.
        private func forgetKeyId(_ keyId: String) {
            lock.lock()
            defer { lock.unlock() }
            guard defaults.string(forKey: StorageKey.appAttestKeyId) == keyId else { return }
            defaults.removeObject(forKey: StorageKey.appAttestKeyId)
            defaults.removeObject(forKey: StorageKey.attestedAppAttestKeyId)
        }
    }

    // ---------------------------------------------------------------------------
    // App Attest call serialization
    // ---------------------------------------------------------------------------

    /// Runs App Attest calls one at a time, in arrival order.
    ///
    /// **Why serialization, rather than a lock around one read:**
    /// `AppleDeviceAttestation.classify(_:keyId:operation:)` maps one Apple
    /// error code, `DCError.invalidKey`, onto three conditions by reading
    /// whether this adapter recorded an attestation for a key, and it discards
    /// that key for one of those three. A second App Attest call running
    /// alongside a first reads that record while the first call's completion
    /// handler is still deciding what to write into it, so a call that Apple
    /// answered "already attested" reads "not attested", takes the rejected-key
    /// row, and deletes a Secure Enclave key Apple had just attested. Holding a
    /// lock across the read alone changes nothing, because the two calls are
    /// still in flight at once and the record is genuinely stale rather than
    /// torn. Running one call at a time is what makes each read follow the
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
        /// - Parameter body: One App Attest call, together with whatever it
        ///   writes into this adapter's stored key state.
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
