#if os(iOS) || os(macOS)

    import CryptoKit
    import DeviceCheck
    import Foundation
    import Security

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
        /// "Sybil resistance and identity uniqueness", states that a missing
        /// device attestation is an expected condition that costs the DID
        /// nothing, so the caller presents no attestation rather than
        /// presenting a weaker one.
        case unsupported(String)
        /// The stored App Attest key ID is missing; call `attest` first.
        case keyNotFound
        /// An internal invariant was violated.
        case internalError(String)
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
    /// Attestation steps (per ADR-025 §"Device attestation"):
    /// 1. `generateKey` — creates a Secure Enclave key via App Attest service.
    /// 2. `attestKey(_:clientDataHash:)` — requests Apple's attestation object
    ///    where `clientDataHash = SHA-256(clientDataJSON)`.
    /// 3. `generateAssertion(_:clientData:)` — per-request proof of possession.
    ///
    /// ## Unavailable service (simulator, or a device without App Attest)
    ///
    /// When `DCAppAttestService.isSupported` is `false`, `attest` and
    /// `assertRequest` throw `AttestationError.unsupported`. The adapter mints
    /// no substitute token, because a locally fabricated token would assert a
    /// hardware guarantee that no hardware produced. §9.3 of the security model
    /// spec, "Sybil resistance and identity uniqueness", records that a DID
    /// carrying no device attestation loses nothing for the absence, so the
    /// honest result is the typed error rather than a token.
    ///
    /// A caller that wants to branch before it calls reads `isHardwareBacked`.
    ///
    /// ## Usage
    ///
    /// ```swift
    /// // App ID = $(AppIdentifierPrefix) followed by
    /// // $(PRODUCT_BUNDLE_IDENTIFIER). $(AppIdentifierPrefix) already ends in
    /// // a period, so concatenate those two settings and add no separator.
    /// let attestation = AppleDeviceAttestation(appId: "A1B2C3D4E5.dev.limn.scp")
    /// ```
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

        /// `SHA-256` of an App ID this adapter attests for.
        ///
        /// Clause 4 of acceptance criterion 3 in ADR-025 requires bytes 0
        /// through 31 of authenticator data to equal `SHA-256` of this app's
        /// App ID, so `verify(token:)` compares those bytes against this
        /// digest.
        private let relyingPartyIdHash: Data

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
        /// - Parameter appId: This app's App ID, written `<team ID>.<bundle ID>`
        ///   — for example `A1B2C3D4E5.dev.limn.scp`. Xcode spells those two
        ///   halves `$(AppIdentifierPrefix)` and `$(PRODUCT_BUNDLE_IDENTIFIER)`.
        ///   `$(AppIdentifierPrefix)` already ends in a period, so joining both
        ///   halves with an added period yields a double period and an App ID
        ///   that matches nothing. Apple binds an App Attest attestation to this
        ///   string, so `verify(token:)` requires a relying-party ID hash equal
        ///   to `SHA-256` of it. No default value exists, because a wrong App ID
        ///   would make `verify(token:)` reject every genuine attestation this
        ///   app produced, and because a caller reads its own team ID and bundle
        ///   ID from its Xcode project.
        ///
        ///   `AppleKeyCustody(accessGroup:)` takes a similar-looking string that
        ///   means something else: a Keychain access group, written
        ///   `<team ID>.dev.limn.scp` whichever app links this SDK. Both strings
        ///   coincide only for an app whose bundle ID is `dev.limn.scp`.
        public init(appId: String) {
            service = DCAppAttestService.shared
            defaults = UserDefaults.standard
            lock = NSLock()
            relyingPartyIdHash = Data(SHA256.hash(data: Data(appId.utf8)))
        }

        /// Testing initializer that accepts injected dependencies.
        ///
        /// Used in unit tests to supply a mock `DCAppAttestService` subclass and
        /// an in-memory `UserDefaults` suite.
        init(appId: String, service: DCAppAttestService, defaults: UserDefaults) {
            self.service = service
            self.defaults = defaults
            lock = NSLock()
            relyingPartyIdHash = Data(SHA256.hash(data: Data(appId.utf8)))
        }

        // MARK: - DeviceAttestationProvider

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
        ///   `AttestationError.serviceError` when the App Attest service
        ///   returns an error on a real device. When that error is
        ///   `DCError.invalidKey`, this method also forgets a stored key ID, so
        ///   a later call generates a replacement key.
        public func attest(challenge: Data, deviceId: Data) async throws -> Data {
            guard service.isSupported else {
                throw AttestationError.unsupported(
                    "DCAppAttestService.isSupported is false on this device, so App Attest cannot "
                        + "produce an attestation. This adapter mints no substitute token."
                )
            }

            let keyId = try await resolveKeyId()
            let clientDataHash = computeClientDataHash(challenge: challenge, deviceId: deviceId)

            return try await withCheckedThrowingContinuation { continuation in
                service.attestKey(keyId, clientDataHash: clientDataHash) { [weak self] attestation, error in
                    if let error {
                        // Apple reports `DCError.invalidKey` when a key ID no
                        // longer names a usable Secure Enclave key, which a
                        // device restore, a rejected key, and an app reinstall
                        // that kept this defaults domain each produce. Apple's
                        // guidance is to discard that key ID and generate a new
                        // key, so this adapter forgets a key ID Apple rejected;
                        // a later `attest` then generates a replacement instead
                        // of failing against a dead key forever.
                        if (error as? DCError)?.code == .invalidKey {
                            self?.forgetKeyId(keyId)
                        }
                        continuation.resume(throwing: AttestationError.serviceError(error.localizedDescription))
                    } else if let attestation {
                        continuation.resume(returning: attestation)
                    } else {
                        continuation.resume(throwing: AttestationError.internalError(
                            "attestKey returned neither attestation nor error"
                        ))
                    }
                }
            }
        }

        /// Generate a per-request assertion for a previously attested key.
        ///
        /// On a real device with App Attest available, calls
        /// `DCAppAttestService.generateAssertion(_:clientData:)`. The assertion
        /// binds the request hash to the stored App Attest key.
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
        ///   `AttestationError.serviceError` when the App Attest service fails.
        public func assertRequest(requestHash: Data) async throws -> Data {
            guard service.isSupported else {
                throw AttestationError.unsupported(
                    "DCAppAttestService.isSupported is false on this device, so App Attest cannot "
                        + "produce an assertion. This adapter mints no substitute token."
                )
            }

            guard let keyId = loadKeyId() else {
                throw AttestationError.keyNotFound
            }

            return try await withCheckedThrowingContinuation { continuation in
                service.generateAssertion(keyId, clientDataHash: requestHash) { [weak self] assertion, error in
                    if let error {
                        // Same key-invalidation path `attest` documents: forget
                        // a key ID Apple rejected, so a later `attest` can
                        // generate a replacement.
                        if (error as? DCError)?.code == .invalidKey {
                            self?.forgetKeyId(keyId)
                        }
                        continuation.resume(throwing: AttestationError.serviceError(error.localizedDescription))
                    } else if let assertion {
                        continuation.resume(returning: assertion)
                    } else {
                        continuation.resume(throwing: AttestationError.internalError(
                            "generateAssertion returned neither assertion nor error"
                        ))
                    }
                }
            }
        }

        // MARK: - Token verification (client-side)

        /// Decide whether `token` is a structurally well-formed Apple App Attest
        /// attestation object.
        ///
        /// **Criterion this method applies:** acceptance criterion 3 of ADR-025
        /// in `.docs/adrs/phase-5.md`, whose four clauses
        /// `AppAttestAttestationObject.isWellFormed(_:relyingPartyIdHash:)`
        /// states in code:
        ///
        /// 1. `token` decodes as one complete CBOR map whose key set is
        ///    exactly `fmt`, `attStmt`, `authData`.
        /// 2. `fmt` holds text `"apple-appattest"`.
        /// 3. `attStmt` holds a CBOR map whose key set is exactly `x5c`,
        ///    `receipt`, where `x5c` holds an array of at least two byte
        ///    strings that each parse as a DER X.509 certificate and whose
        ///    element 0 names element 1 as its issuer, and `receipt` holds a
        ///    byte string.
        /// 4. `authData` holds a byte string of at least 87 bytes whose first
        ///    32 bytes equal `SHA-256` of an App ID this adapter was
        ///    initialized with, whose bytes 37 through 52 equal one of two App
        ///    Attest AAGUIDs, and whose bytes 53 and 54 equal `0x00 0x20`.
        ///
        /// A token that fails any clause makes this method return `false`.
        ///
        /// **What this method does not decide:** it checks no signature, it
        /// checks no certificate chain, and it checks no challenge binding. An
        /// SCP relay performs those checks by calling Apple's App Attest
        /// attestation endpoint. A `true` result here means a relay received
        /// something worth checking, never that a relay will accept it.
        ///
        /// - Parameter token: Raw attestation bytes to validate.
        /// - Returns: `true` when `token` satisfies all four clauses above,
        ///   `false` for every other input.
        public func verify(token: Data) -> Bool {
            AppAttestAttestationObject.isWellFormed(token, relyingPartyIdHash: relyingPartyIdHash)
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
        ///   `attestKey(_:clientDataHash:)` and `generateAssertion(_:clientData:)`.
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
        /// The relay reconstructs this JSON with the same fixed-field-order formula
        /// to verify the nonce embedded in the App Attest leaf certificate.
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
        /// Thread-safe: protected by `lock`.
        ///
        /// - Parameter keyId: The key ID returned by
        ///   `DCAppAttestService.generateKey`.
        private func storeKeyId(_ keyId: String) {
            lock.lock()
            defer { lock.unlock() }
            defaults.set(keyId, forKey: StorageKey.appAttestKeyId)
        }

        /// Remove a stored App Attest key ID, unless another key ID replaced it.
        ///
        /// Thread-safe: protected by `lock`.
        ///
        /// - Parameter keyId: A key ID Apple reported as invalid. Removing only
        ///   this value keeps a concurrent regeneration's key ID in place.
        private func forgetKeyId(_ keyId: String) {
            lock.lock()
            defer { lock.unlock() }
            guard defaults.string(forKey: StorageKey.appAttestKeyId) == keyId else { return }
            defaults.removeObject(forKey: StorageKey.appAttestKeyId)
        }
    }

    // ---------------------------------------------------------------------------
    // App Attest attestation-object structure
    // ---------------------------------------------------------------------------

    /// Decides whether a byte string is an Apple App Attest attestation object.
    ///
    /// Apple's `DCAppAttestService.attestKey(_:clientDataHash:)` returns an
    /// attestation in a WebAuthn attestation-object shape, documented in
    /// Apple's article "Validating Apps That Connect to Your Server": a CBOR map
    /// holding `fmt`, `attStmt`, and `authData`, where `fmt` holds text
    /// `"apple-appattest"`.
    ///
    /// `isWellFormed(_:relyingPartyIdHash:)` applies four clauses of acceptance
    /// criterion 3 in ADR-025, `.docs/adrs/phase-5.md`. Each clause names which
    /// values it permits, so an accepted set stays closed by construction
    /// rather than by a list of rejected spellings. A token Apple did not
    /// produce fails this check unless someone rebuilt a whole
    /// attestation-object structure for this app's App ID, and even then an SCP
    /// relay rejects it because it carries no Apple signature.
    enum AppAttestAttestationObject {
        /// Three keys an App Attest attestation object carries, and only three
        /// keys clause 1 accepts.
        private enum Key: String, CaseIterable {
            case format = "fmt"
            case attestationStatement = "attStmt"
            case authenticatorData = "authData"
        }

        /// Two keys an App Attest attestation statement carries, and only two
        /// keys clause 3 accepts.
        private enum StatementKey: String, CaseIterable {
            case certificateChain = "x5c"
            case receipt
        }

        /// A `fmt` value Apple writes into every App Attest attestation object.
        private static let appleAttestationFormat = "apple-appattest"

        /// Fewest certificates clause 3 accepts in `x5c`: a credential
        /// certificate and an Apple App Attest intermediate certificate.
        private static let minimumCertificateCount = 2

        /// Shortest authenticator data clause 4 accepts: a 32-byte
        /// relying-party ID hash, one flags byte, a 4-byte sign counter, a
        /// 16-byte AAGUID, a 2-byte credential-ID length, and a 32-byte
        /// credential ID.
        private static let minimumAuthenticatorDataLength = 87

        /// How many authenticator-data bytes a relying-party ID hash occupies,
        /// starting at byte 0.
        private static let relyingPartyIdHashLength = 32

        /// Where an AAGUID starts inside authenticator data, and how many bytes
        /// it occupies.
        private static let aaguidOffset = 37
        private static let aaguidLength = 16

        /// Where a credential-ID length starts inside authenticator data.
        private static let credentialIdLengthOffset = 53

        /// An AAGUID a production App Attest key carries: ASCII bytes of
        /// `appattest` followed by seven zero bytes.
        private static let productionAaguid = [UInt8]("appattest".utf8) + [UInt8](repeating: 0, count: 7)

        /// An AAGUID a development App Attest key carries: sixteen ASCII bytes
        /// of `appattestdevelop`, which need no padding.
        private static let developmentAaguid = [UInt8]("appattestdevelop".utf8)

        /// A credential-ID length App Attest writes: 32 encoded as a big-endian
        /// `UInt16`.
        private static let credentialIdLengthBytes: [UInt8] = [0x00, 0x20]

        /// Report whether `token` satisfies all four clauses of acceptance
        /// criterion 3 in ADR-025.
        ///
        /// - Parameters:
        ///   - token: Raw bytes a caller received as an attestation.
        ///   - relyingPartyIdHash: `SHA-256` of an App ID a caller attests for,
        ///     which clause 4 requires bytes 0 through 31 of authenticator data
        ///     to equal.
        /// - Returns: `true` only for a complete, correctly keyed,
        ///   definite-length CBOR attestation object whose attestation
        ///   statement and authenticator data satisfy clauses 3 and 4; `false`
        ///   for every other input.
        static func isWellFormed(_ token: Data, relyingPartyIdHash: Data) -> Bool {
            var reader = CBORReader(token)
            guard let entryCount = reader.readMapHeader(),
                  entryCount == Key.allCases.count else { return false }

            // A map carrying `Key.allCases.count` entries, no key twice and no
            // key outside `Key`, carries each of three keys exactly once.
            var seenKeys = Set<Key>()
            for _ in 0 ..< entryCount {
                guard let name = reader.readTextString(),
                      let key = Key(rawValue: name),
                      seenKeys.insert(key).inserted,
                      readValue(
                          for: key,
                          from: &reader,
                          relyingPartyIdHash: relyingPartyIdHash
                      ) else { return false }
            }

            return reader.isAtEnd
        }

        /// Consume a value that follows `key` and report whether that value
        /// satisfies a constraint `key` imposes.
        private static func readValue(
            for key: Key,
            from reader: inout CBORReader,
            relyingPartyIdHash: Data
        ) -> Bool {
            switch key {
            case .format:
                return reader.readTextString() == appleAttestationFormat
            case .attestationStatement:
                return readAttestationStatement(from: &reader)
            case .authenticatorData:
                return readAuthenticatorData(from: &reader, relyingPartyIdHash: relyingPartyIdHash)
            }
        }

        /// Apply clause 3 to an `attStmt` value: a CBOR map whose key set is
        /// exactly `x5c` and `receipt`.
        private static func readAttestationStatement(from reader: inout CBORReader) -> Bool {
            guard let entryCount = reader.readMapHeader(),
                  entryCount == StatementKey.allCases.count else { return false }

            var seenKeys = Set<StatementKey>()
            for _ in 0 ..< entryCount {
                guard let name = reader.readTextString(),
                      let key = StatementKey(rawValue: name),
                      seenKeys.insert(key).inserted,
                      readStatementValue(for: key, from: &reader) else { return false }
            }
            return true
        }

        /// Consume a value that follows a statement key and report whether that
        /// value satisfies a constraint clause 3 puts on that key.
        private static func readStatementValue(
            for key: StatementKey,
            from reader: inout CBORReader
        ) -> Bool {
            switch key {
            case .certificateChain:
                return readCertificateChain(from: &reader)
            case .receipt:
                return reader.readByteString() != nil
            }
        }

        /// Apply clause 3 to an `x5c` value: an array of at least two byte
        /// strings that each parse as a DER X.509 certificate, where element 0
        /// is a credential certificate and element 1 is an issuing App Attest
        /// intermediate certificate.
        ///
        /// Position carries meaning, so this method requires element 0's issuer
        /// name to equal element 1's subject name. Two unrelated certificates
        /// in either order fail that requirement.
        ///
        /// Which certification authority element 1 belongs to stays undecided
        /// here. An SCP relay decides that by calling Apple's App Attest
        /// attestation endpoint, which walks a chain to Apple's App Attest
        /// root, and ADR-025 assigns that decision to a relay.
        private static func readCertificateChain(from reader: inout CBORReader) -> Bool {
            guard let certificateCount = reader.readArrayHeader(),
                  certificateCount >= minimumCertificateCount else { return false }

            var credential: SecCertificate?
            var issuer: SecCertificate?
            for position in 0 ..< certificateCount {
                guard let der = reader.readByteString(),
                      let certificate = parseCertificate(der) else { return false }
                if position == 0 {
                    credential = certificate
                }
                if position == 1 {
                    issuer = certificate
                }
            }

            guard let credential, let issuer,
                  let credentialIssuerName = SecCertificateCopyNormalizedIssuerSequence(credential),
                  let issuerSubjectName = SecCertificateCopyNormalizedSubjectSequence(issuer)
            else { return false }
            return CFEqual(credentialIssuerName, issuerSubjectName)
        }

        /// Parse `der` as a DER-encoded X.509 certificate, or report `nil`.
        ///
        /// `SecCertificateCreateWithData` returns `nil` for bytes that are not
        /// a DER X.509 certificate, so it decides clause 3's certificate
        /// requirement by parsing rather than by matching a byte prefix. It
        /// builds no trust evaluation and checks no signature.
        private static func parseCertificate(_ der: ArraySlice<UInt8>) -> SecCertificate? {
            SecCertificateCreateWithData(nil, Data(der) as CFData)
        }

        /// Apply clause 4 to an `authData` value: a byte string of at least 87
        /// bytes carrying attested credential data for this app.
        ///
        /// Clause 4 constrains three fields by value and leaves three fields
        /// unconstrained. It fixes a relying-party ID hash, an AAGUID, and a
        /// credential-ID length. It fixes no value for a flags byte, for a sign
        /// counter, or for 32 credential-ID bytes, so this method reads none of
        /// those three fields and rejects nothing on their contents.
        private static func readAuthenticatorData(
            from reader: inout CBORReader,
            relyingPartyIdHash: Data
        ) -> Bool {
            guard let authenticatorData = reader.readByteString(),
                  authenticatorData.count >= minimumAuthenticatorDataLength else { return false }

            // `prefix` and `dropFirst` count from a slice's own start, so these
            // three field reads need no index arithmetic and copy no bytes.
            let relyingPartyIdHashField = authenticatorData.prefix(relyingPartyIdHashLength)
            guard relyingPartyIdHashField.elementsEqual(relyingPartyIdHash) else { return false }

            // Apple's article "Validating Apps That Connect to Your Server"
            // instructs a verifier to expect `appattestdevelop` from an app
            // running in App Attest's development environment, and `appattest`
            // followed by seven zero bytes from an app running in App Attest's
            // production environment. A provisioning profile picks between
            // those two environments when Xcode builds an app, and entitlement
            // `com.apple.developer.devicecheck.appattest-environment` overrides
            // that pick. No public API on iOS reads either value.
            //
            // This method therefore accepts both AAGUIDs and selects neither,
            // which is what clause 4 of acceptance criterion 3 states. Guessing
            // an environment from a surface feature — a sandbox App Store
            // receipt, say — would substitute an indicator for a criterion, and
            // guessing wrong would reject every genuine attestation a
            // development build produced. A caller that needs production
            // enforced pins it with that entitlement, where Apple's own service
            // enforces it.
            let aaguidField = authenticatorData.dropFirst(aaguidOffset).prefix(aaguidLength)
            guard aaguidField.elementsEqual(productionAaguid)
                || aaguidField.elementsEqual(developmentAaguid) else { return false }

            let credentialIdLengthField = authenticatorData
                .dropFirst(credentialIdLengthOffset)
                .prefix(credentialIdLengthBytes.count)
            return credentialIdLengthField.elementsEqual(credentialIdLengthBytes)
        }
    }

    /// Reads four CBOR (RFC 8949) item types that acceptance criterion 3 names:
    /// definite-length byte strings, text strings, arrays, and maps.
    ///
    /// Each read demands one major type and returns `nil` for every other major
    /// type, so an indefinite-length item, a reserved additional-information
    /// value, a tag, an integer, and a floating-point item each fail wherever
    /// they appear. This reader never traps and never reads past an end of its
    /// buffer. It also walks no nesting that criterion 3 leaves unnamed — an
    /// attestation object nests three levels, from an object to `attStmt` to an
    /// `x5c` array — so a crafted token cannot drive it into deep recursion.
    private struct CBORReader {
        private let bytes: [UInt8]
        private var index: Int

        init(_ data: Data) {
            bytes = [UInt8](data)
            index = 0
        }

        /// Whether the reader consumed every byte it was given.
        var isAtEnd: Bool {
            index == bytes.count
        }

        /// How many bytes the reader has not consumed.
        private var remainingCount: Int {
            bytes.count - index
        }

        /// Read one byte, or return `nil` when the buffer holds none.
        private mutating func readByte() -> UInt8? {
            guard index < bytes.count else { return nil }
            defer { index += 1 }
            return bytes[index]
        }

        /// Read the major type and the argument of one CBOR item head.
        ///
        /// - Returns: `nil` when the input truncates mid-head, when the
        ///   additional-information value is reserved (28 through 30), or when
        ///   the item declares an indefinite length (31).
        private mutating func readHead() -> (major: UInt8, argument: UInt64)? {
            guard let initialByte = readByte() else { return nil }
            let major = initialByte >> 5
            let additional = initialByte & 0x1F
            switch additional {
            case 0 ... 23:
                return (major, UInt64(additional))
            case 24 ... 27:
                let width = 1 << Int(additional - 24)
                var argument: UInt64 = 0
                for _ in 0 ..< width {
                    guard let next = readByte() else { return nil }
                    argument = (argument << 8) | UInt64(next)
                }
                return (major, argument)
            default:
                return nil
            }
        }

        /// Consume `count` payload bytes, or return `nil` when the buffer holds
        /// fewer than `count` bytes.
        private mutating func consumePayload(count: UInt64) -> Int? {
            guard count <= UInt64(remainingCount) else { return nil }
            let length = Int(count)
            index += length
            return length
        }

        /// Read a definite-length text string and decode it as UTF-8.
        mutating func readTextString() -> String? {
            guard let head = readHead(), head.major == 3 else { return nil }
            let start = index
            guard consumePayload(count: head.argument) != nil else { return nil }
            return String(bytes: bytes[start ..< index], encoding: .utf8)
        }

        /// Read a definite-length byte string and return its payload bytes.
        mutating func readByteString() -> ArraySlice<UInt8>? {
            guard let head = readHead(), head.major == 2 else { return nil }
            let start = index
            guard consumePayload(count: head.argument) != nil else { return nil }
            return bytes[start ..< index]
        }

        /// Read a definite-length map head and report its entry count.
        ///
        /// Each entry costs at least two bytes, so a declared count larger than
        /// how many bytes remain cannot be satisfied, and this reader rejects
        /// such a count without looping. That bound is one byte per entry, so
        /// it admits some counts a two-bytes-per-entry bound would reject; it
        /// exists to cap work, and a caller decides which counts it accepts.
        mutating func readMapHeader() -> Int? {
            readContainerHeader(major: 5)
        }

        /// Read a definite-length array head and report its element count.
        ///
        /// Each element costs at least one byte, so a declared count larger than
        /// how many bytes remain cannot be satisfied, and this reader rejects
        /// such a count without looping.
        mutating func readArrayHeader() -> Int? {
            readContainerHeader(major: 4)
        }

        /// Read a definite-length head of one major type and report which entry
        /// count it declares.
        private mutating func readContainerHeader(major: UInt8) -> Int? {
            guard let head = readHead(), head.major == major,
                  head.argument <= UInt64(remainingCount) else { return nil }
            return Int(head.argument)
        }
    }

#endif // os(iOS) || os(macOS)
