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
        /// Apple answered `attestKey` with `DCError.invalidKey` for a key it
        /// had already attested, which a successful assertion with that key
        /// showed.
        ///
        /// `DCError.h` lists "you call `attestKey:clientDataHash:` for a key
        /// that's already been attested" as one cause of that code. This
        /// adapter reaches it only when an earlier attestation succeeded and
        /// its record was lost. It keeps that key and records the attestation,
        /// so a later `attest(challenge:deviceId:)` generates a replacement
        /// key.
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
        /// Apple could not reach its App Attest service during an attestation
        /// or an assertion.
        ///
        /// `DCError.h` instructs a caller to "try the attestation again later
        /// using the same key and the same value for the `clientDataHash`
        /// parameter", because "retrying with the same inputs helps to preserve
        /// the risk metric for a given device". This adapter keeps that key, so
        /// a retry reaches Apple with a key Apple already saw.
        case serverUnavailable(String)
        /// An internal invariant was violated.
        case internalError(String)
        /// The attestation `challenge` or the assertion `requestHash` is not 32
        /// bytes, so it is not the binding digest `D` or the assertion digest
        /// `A` of `09-security-model.md` §9.3.1 that App Attest takes as
        /// `clientDataHash`.
        case invalidChallenge(String)
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
            case let .invalidChallenge(msg): .Identity(msg: msg, code: "SCP-ATTEST-9026")
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
        /// Apple attests one key once, so this record is what makes `attest`
        /// generate a replacement key, and it tells the two conditions
        /// `generateAssertion` answers `DCError.invalidKey` for apart. This key
        /// holds a key ID rather than a flag, so a stale value cannot describe
        /// a key ID that replaced it.
        static let attestedAppAttestKeyId = "dev.limn.scp.appAttest.attestedKeyId"

        /// `UserDefaults` key under which a key generated to replace an attested
        /// key is persisted until Apple attests it.
        ///
        /// `appAttestKeyId` keeps naming the attested key until then, so an
        /// `attestKey` failure on the replacement leaves `assertRequest` with
        /// the key an earlier published attestation names.
        static let replacementAppAttestKeyId = "dev.limn.scp.appAttest.replacementKeyId"
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
    /// persisted in `UserDefaults`: assertions use the stored key, and an
    /// attestation reuses it only while Apple has not attested it. A key
    /// generated to replace an attested key is stored apart from it, and it
    /// becomes the stored key only after Apple attests it.
    ///
    /// Attestation steps (per ADR-025 acceptance criterion 3):
    /// 1. `generateKey` — creates a Secure Enclave key via App Attest service.
    /// 2. `attestKey(_:clientDataHash:)` — requests Apple's attestation object,
    ///    with the 32-byte `challenge` as `clientDataHash`, unchanged.
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
    /// `AppleDeviceAttestation` is `final` and conforms to `Sendable`. Its
    /// `UserDefaults` reads and writes are protected by `NSLock`.
    /// `callSerializer`, an actor, runs every `attest` and `assertRequest`
    /// body, key generation included, one at a time in arrival order, and
    /// `resolveKeyId()` and `classify(_:keyId:operation:)` are correct only
    /// under that ordering. `attestKey` and `generateAssertion` bridge to
    /// structured concurrency through `withCheckedContinuation` and return
    /// Apple's answer as a `Result`; `generateKey` bridges through
    /// `withCheckedThrowingContinuation`.
    ///
    /// The lock and the serializer belong to one instance, while
    /// `UserDefaults.standard` and `DCAppAttestService.shared`, which `init()`
    /// reads, belong to the process. Two instances built with `init()`
    /// therefore race on one stored key ID and one attestation record: each can
    /// generate a key, and one can discard a key Apple attested for the other.
    /// A host builds one `AppleDeviceAttestation` per process.
    ///
    /// See ADR-025 and `crates/scp-platform/src/traits.rs` `DeviceAttestation`.
    public final class AppleDeviceAttestation: DeviceAttestationProvider, @unchecked Sendable {
        // `@unchecked Sendable` is required because this class is injected into the
        // Rust engine via the UniFFI `DeviceAttestationProvider` callback interface,
        // which requires `Send + Sync` (Rust) → `Sendable` (Swift). Internal mutable
        // state (`UserDefaults`) is protected by `lock`; no reference
        // semantics escape across the FFI boundary. This is the same exception as
        // `MessageListenerAdapter`. See .docs/standards/swift.md §Sendable — UniFFI exception.

        private let service: DCAppAttestService
        private let defaults: UserDefaults
        private let lock: NSLock

        /// Runs one App Attest call at a time, so `classify(_:keyId:operation:)`
        /// reads an attestation record no other call is concurrently writing,
        /// each call reads the stored key ID after every preceding call
        /// finished writing it, and concurrent `attest` calls generate one key.
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

        /// Generate an attestation for the given challenge.
        ///
        /// On a real device with App Attest available:
        /// 1. Checks that `challenge` is 32 bytes, before any App Attest call.
        /// 2. Retrieves a stored replacement key ID, or the stored key ID while
        ///    Apple has not attested it, or generates and stores a new key. A
        ///    key generated while the stored key is attested is stored as the
        ///    replacement, and it becomes the stored key only after Apple
        ///    attests it.
        /// 3. Calls `DCAppAttestService.attestKey(_:clientDataHash:)` with
        ///    `challenge` as `clientDataHash`, unchanged.
        /// 4. Returns the raw CBOR attestation object Apple signed.
        ///
        /// ADR-025 acceptance criterion 3 has the Rust core pass the binding
        /// digest of `09-security-model.md` §9.3.1 as `challenge`, and a reader
        /// verifies the attestation under that section. This adapter does not
        /// verify, and it does not read `deviceId`, because the digest already
        /// binds the identity. §9.3.1 keeps one attestation per context, so
        /// every successful call attests a key no earlier call attested.
        ///
        /// On simulator or on a device where App Attest is unavailable, this
        /// method throws `AttestationError.unsupported` and returns no bytes.
        ///
        /// - Parameters:
        ///   - challenge: The 32-byte §9.3.1 binding digest.
        ///   - deviceId: Not read by this adapter.
        /// - Returns: The raw CBOR attestation object that Apple signed.
        /// - Throws: `AttestationError.unsupported` when
        ///   `DCAppAttestService.isSupported` is `false`.
        ///   `AttestationError.invalidChallenge` when `challenge` is not 32
        ///   bytes; this method then generates no key and calls no App Attest
        ///   method.
        ///   `AttestationError.keyAlreadyAttested` when Apple already attested
        ///   the stored key although this adapter held no record of it; this
        ///   method records that attestation, so a later call generates a
        ///   replacement key.
        ///   `AttestationError.keyRejected` when Apple's App Attest service
        ///   rejected the stored key; this method discards its key ID, so a
        ///   later call generates a replacement.
        ///   `AttestationError.serverUnavailable` when Apple could not reach its
        ///   App Attest service; this method keeps that key, so a retry reaches
        ///   Apple with a key Apple already saw.
        ///   `AttestationError.serviceError` for every other App Attest error.
        ///   `classify(_:keyId:operation:)` states which condition each
        ///   `DCError.invalidKey` maps to.
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
                throw AttestationError.invalidChallenge(
                    "the attestation challenge is \(challenge.count) bytes; App Attest takes the "
                        + "32-byte binding digest of 09-security-model.md §9.3.1 as clientDataHash"
                )
            }

            // The key ID is read inside the serialized body, because a call
            // queued behind a predecessor that discarded, attested or replaced
            // the key would otherwise reach Apple with a key ID whose state
            // this adapter no longer describes, and
            // `classify(_:keyId:operation:)` would then name a condition that
            // does not hold.
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
                switch await self.callAttestKey(keyId, clientDataHash: challenge) {
                case let .success(attestation):
                    // Apple attests one key once, so this record is what makes
                    // the next `attest` generate a replacement key and what
                    // tells `classify` which `DCError.invalidKey` condition
                    // holds. A serialized successor starts after this write.
                    self.markKeyAttested(keyId)
                    return .success(attestation)
                case let .failure(error):
                    return await .failure(self.classify(error, keyId: keyId, operation: .attestation))
                }
            }
            return try outcome.get()
        }

        /// Generate a per-request assertion for a previously attested key.
        ///
        /// On a real device with App Attest available, calls
        /// `DCAppAttestService.generateAssertion(_:clientDataHash:)` and passes
        /// `requestHash` as `clientDataHash` unchanged. ADR-025 acceptance
        /// criterion 3 has the Rust core pass the assertion digest `A` of
        /// `09-security-model.md` §9.3.1 as `requestHash`.
        ///
        /// On simulator or on a device where App Attest is unavailable, this
        /// method throws `AttestationError.unsupported` and returns no bytes.
        ///
        /// - Parameter requestHash: The 32-byte digest the assertion binds.
        /// - Returns: The raw CBOR assertion object Apple produced.
        /// - Throws: `AttestationError.unsupported` when
        ///   `DCAppAttestService.isSupported` is `false`.
        ///   `AttestationError.invalidChallenge` when `requestHash` is not 32
        ///   bytes; this method then calls no App Attest method.
        ///   `AttestationError.keyNotFound` when no key ID is stored, which
        ///   happens when no caller has called `attest` yet.
        ///   `AttestationError.keyNotAttested` when a key ID is stored and Apple
        ///   attested no key, which makes `attest(challenge:deviceId:)` a
        ///   caller's next call; this method keeps that key.
        ///   `AttestationError.keyRejected` when Apple's App Attest service
        ///   rejected an attested key; this method discards its key ID.
        ///   `AttestationError.serverUnavailable` when Apple could not reach its
        ///   App Attest service; this method keeps that key.
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
            guard requestHash.count == 32 else {
                throw AttestationError.invalidChallenge(
                    "the assertion request hash is \(requestHash.count) bytes; App Attest takes the "
                        + "32-byte assertion digest A of 09-security-model.md §9.3.1 as clientDataHash"
                )
            }

            // The key ID is read inside the serialized body for the reason
            // `attest(challenge:deviceId:)` states.
            let outcome = await callSerializer.run { [weak self] () -> Result<Data, AttestationError> in
                guard let self else { return .failure(.internalError("self was deallocated")) }
                guard let keyId = self.loadKeyId() else { return .failure(.keyNotFound) }
                switch await self.callGenerateAssertion(keyId, clientDataHash: requestHash) {
                case let .success(assertion):
                    return .success(assertion)
                case let .failure(error):
                    return await .failure(self.classify(error, keyId: keyId, operation: .assertion))
                }
            }
            return try outcome.get()
        }

        /// Call `attestKey(_:clientDataHash:)` once and return Apple's answer
        /// untranslated. A caller reaches this method through `callSerializer`.
        private func callAttestKey(_ keyId: String, clientDataHash: Data) async -> Result<Data, Error> {
            await withCheckedContinuation { continuation in
                service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
                    continuation.resume(returning: Self.completionResult(attestation, error, call: "attestKey"))
                }
            }
        }

        /// Call `generateAssertion(_:clientDataHash:)` once and return Apple's
        /// answer untranslated. A caller reaches this method through
        /// `callSerializer`.
        private func callGenerateAssertion(_ keyId: String, clientDataHash: Data) async -> Result<Data, Error> {
            await withCheckedContinuation { continuation in
                service.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
                    continuation.resume(returning: Self.completionResult(assertion, error, call: "generateAssertion"))
                }
            }
        }

        /// Turn an App Attest completion handler's two optionals into one
        /// result; an answer with neither is `AttestationError.internalError`.
        private static func completionResult(_ value: Data?, _ error: Error?, call: String) -> Result<Data, Error> {
            if let error {
                return .failure(error)
            }
            if let value {
                return .success(value)
            }
            return .failure(AttestationError.internalError("\(call) returned neither a value nor an error"))
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

        /// The `clientDataHash` of the assertion that tells an already-attested
        /// key from a rejected one: the key-probe input `K` of
        /// `09-security-model.md` §9.3.1, whose separator §9.18.2 registers.
        /// Apple signs it with the stored key, and this adapter discards that
        /// assertion.
        private static let keyProbeClientDataHash = Data(SHA256.hash(data: Data("SCP-APP-ATTEST-KEY-PROBE-V1".utf8)))

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
        /// `attest` names only a key with no attestation record, so a record
        /// cannot separate the two conditions `attestKey` can raise, and this
        /// method asks Apple for an assertion with that key instead:
        ///
        /// | Call | Evidence | Condition | Key |
        /// | --- | --- | --- | --- |
        /// | `attestKey` | probe assertion succeeds | already attested | kept, recorded |
        /// | `attestKey` | probe answers `invalidKey` | service rejected it | discarded |
        /// | `attestKey` | probe answers `serverUnavailable` | unknown (`serverUnavailable`) | kept |
        /// | `attestKey` | probe fails otherwise | unknown (`serviceError`) | kept |
        /// | `generateAssertion` | no record | unattested key | kept |
        /// | `generateAssertion` | record | service rejected it | discarded |
        ///
        /// `DCError.serverUnavailable` from either call keeps the key, because
        /// `DCError.h` asks a caller to retry with the same key.
        ///
        /// **What makes an attestation record a sound input.** The record
        /// describes the key App Attest holds only while no other App Attest
        /// call for that key is outstanding. `callSerializer` runs one App
        /// Attest call at a time, and each call reads the stored key ID inside
        /// its serialized body, so every read here follows every write a
        /// preceding call made.
        private func classify(
            _ error: Error,
            keyId: String,
            operation: AppAttestOperation
        ) async -> AttestationError {
            if let error = error as? AttestationError {
                return error
            }
            guard let code = (error as? DCError)?.code else {
                return .serviceError(error.localizedDescription)
            }
            switch code {
            case .serverUnavailable:
                return .serverUnavailable(error.localizedDescription)
            case .invalidKey:
                switch operation {
                case .attestation:
                    return await probeKeyAfterInvalidAttestation(keyId, error)
                case .assertion:
                    guard isKeyAttested(keyId) else {
                        return .keyNotAttested(
                            "App Attest holds no attestation for this key, so attest it before asking "
                                + "for an assertion: \(error.localizedDescription)"
                        )
                    }
                    return rejectKey(keyId, error)
                }
            default:
                return .serviceError(error.localizedDescription)
            }
        }

        /// Ask Apple for an assertion with a key `attestKey` answered
        /// `DCError.invalidKey` for, and read the three `attestKey` rows of
        /// `classify(_:keyId:operation:)` from that answer.
        private func probeKeyAfterInvalidAttestation(_ keyId: String, _ error: Error) async -> AttestationError {
            switch await callGenerateAssertion(keyId, clientDataHash: Self.keyProbeClientDataHash) {
            case .success:
                markKeyAttested(keyId)
                return .keyAlreadyAttested(
                    "App Attest already attested this key, so a later attest generates a "
                        + "replacement key: \(error.localizedDescription)"
                )
            case let .failure(probeError) where (probeError as? DCError)?.code == .invalidKey:
                return rejectKey(keyId, error)
            case let .failure(probeError) where (probeError as? DCError)?.code == .serverUnavailable:
                return .serverUnavailable(
                    "attestKey answered invalidKey and the assertion that tells an attested key "
                        + "from a rejected one could not reach Apple: \(probeError.localizedDescription)"
                )
            case let .failure(probeError):
                return .serviceError(
                    "attestKey answered invalidKey and the assertion that tells an attested key "
                        + "from a rejected one failed: \(probeError.localizedDescription)"
                )
            }
        }

        /// Discard a key Apple's App Attest service rejected.
        private func rejectKey(_ keyId: String, _ error: Error) -> AttestationError {
            forgetKeyId(keyId)
            return .keyRejected(
                "App Attest rejected this device's key, and this adapter discarded its key "
                    + "ID, so a later attest generates a replacement: \(error.localizedDescription)"
            )
        }

        // MARK: - Private helpers

        /// Return the key ID the next `attestKey` names: a stored replacement
        /// key, else the stored key while Apple has not attested it, else a
        /// newly generated key.
        ///
        /// A caller reaches this method through `callSerializer`, which is what
        /// makes concurrent callers generate one key rather than one each.
        /// §9.3.1 of `09-security-model.md` keeps one attestation per context,
        /// and Apple attests one key once, so a key this adapter recorded as
        /// attested is never handed to `attestKey` again.
        ///
        /// - Returns: An App Attest key ID with no attestation record.
        /// - Throws: `AttestationError.serviceError` if `generateKey` fails.
        private func resolveKeyId() async throws -> String {
            if let replacement = loadReplacementKeyId() {
                return replacement
            }
            if let stored = loadKeyId(), !isKeyAttested(stored) {
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

        /// Load a replacement App Attest key ID Apple has not attested yet.
        ///
        /// Thread-safe: protected by `lock`.
        private func loadReplacementKeyId() -> String? {
            lock.lock()
            defer { lock.unlock() }
            return defaults.string(forKey: StorageKey.replacementAppAttestKeyId)
        }

        /// Persist a freshly generated App Attest key ID to `UserDefaults`.
        ///
        /// While the stored key carries an attestation record, this method
        /// stores the new key ID as the replacement and leaves the attested key
        /// and its record in place, so `assertRequest` keeps asserting with the
        /// attested key until `markKeyAttested(_:)` promotes the replacement.
        /// Otherwise it stores the new key ID as the stored key and removes any
        /// recorded attestation, which keeps a record left by a previous key
        /// from describing this one.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// - Parameter keyId: The key ID returned by
        ///   `DCAppAttestService.generateKey`.
        private func storeKeyId(_ keyId: String) {
            lock.lock()
            defer { lock.unlock() }
            let stored = defaults.string(forKey: StorageKey.appAttestKeyId)
            if let stored, defaults.string(forKey: StorageKey.attestedAppAttestKeyId) == stored {
                defaults.set(keyId, forKey: StorageKey.replacementAppAttestKeyId)
                return
            }
            defaults.set(keyId, forKey: StorageKey.appAttestKeyId)
            defaults.removeObject(forKey: StorageKey.attestedAppAttestKeyId)
            defaults.removeObject(forKey: StorageKey.replacementAppAttestKeyId)
        }

        /// Record that Apple attested `keyId`.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// A replacement key Apple attested becomes the stored key, which
        /// retires the key it replaced.
        ///
        /// - Parameter keyId: A key ID Apple attested. Recording it only while
        ///   it is still this adapter's replacement or stored key ID keeps a
        ///   concurrent regeneration's key ID from inheriting an attestation
        ///   Apple granted to a key it replaced.
        private func markKeyAttested(_ keyId: String) {
            lock.lock()
            defer { lock.unlock() }
            if defaults.string(forKey: StorageKey.replacementAppAttestKeyId) == keyId {
                defaults.set(keyId, forKey: StorageKey.appAttestKeyId)
                defaults.removeObject(forKey: StorageKey.replacementAppAttestKeyId)
            } else if defaults.string(forKey: StorageKey.appAttestKeyId) != keyId {
                return
            }
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

        /// Remove a replacement or stored App Attest key ID, and any
        /// attestation recorded for a stored one, unless another key ID
        /// replaced it.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// - Parameter keyId: A key ID Apple's App Attest service rejected.
        ///   Removing only this value keeps a concurrent regeneration's key ID
        ///   in place, and removing a rejected replacement leaves the attested
        ///   key it was meant to replace in place.
        private func forgetKeyId(_ keyId: String) {
            lock.lock()
            defer { lock.unlock() }
            if defaults.string(forKey: StorageKey.replacementAppAttestKeyId) == keyId {
                defaults.removeObject(forKey: StorageKey.replacementAppAttestKeyId)
                return
            }
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
    /// alongside a first reads that record while the first call is still
    /// deciding what to write into it, so an assertion Apple answered
    /// "unattested key" can read "attested", take the rejected-key row, and
    /// delete a Secure Enclave key Apple had just attested. Holding a
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
