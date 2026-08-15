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
        ///   returns an error on a real device.
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
                service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
                    if let error {
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
                service.generateAssertion(keyId, clientDataHash: requestHash) { assertion, error in
                    if let error {
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
        /// **The criterion this method applies:** the bytes decode as one
        /// complete CBOR map that carries exactly the three entries
        /// `fmt`, `attStmt`, and `authData`, where `fmt` holds the text
        /// `"apple-appattest"`, `attStmt` holds a map, and `authData` holds a
        /// byte string of at least 37 bytes. `AppAttestAttestationObject`
        /// states the criterion in code and rejects everything else, so a
        /// caller can rely on this method to return `false`.
        ///
        /// **What this method does not decide:** it checks no signature and no
        /// certificate chain. The SCP relay performs that check by calling
        /// Apple's App Attest attestation endpoint. A `true` result here means
        /// the relay received something worth checking, never that the relay
        /// will accept it.
        ///
        /// - Parameter token: Raw attestation bytes to validate.
        /// - Returns: `true` when the token satisfies the structural criterion
        ///   above, `false` for every other input.
        public func verify(token: Data) -> Bool {
            AppAttestAttestationObject.isWellFormed(token)
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
        ///   `attestKey(_:clientDataHash:)` and `generateAssertion(_:clientData:)`.
        /// - Throws: `AttestationError.serviceError` if `generateKey` fails.
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
                let task = Task<String, Error> { [weak self] in
                    guard let self else { throw AttestationError.internalError("self was deallocated") }
                    return try await self.generateAndStoreKey()
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
    }

    // ---------------------------------------------------------------------------
    // App Attest attestation-object structure
    // ---------------------------------------------------------------------------

    /// Decides whether a byte string is an Apple App Attest attestation object.
    ///
    /// Apple's `DCAppAttestService.attestKey(_:clientDataHash:)` returns the
    /// attestation in the WebAuthn attestation-object shape, documented in
    /// Apple's article "Validating Apps That Connect to Your Server": a CBOR map
    /// holding `fmt`, `attStmt`, and `authData`, where `fmt` is the text
    /// `"apple-appattest"`.
    ///
    /// `isWellFormed` names the three permitted keys and rejects every other
    /// key, so the accepted set is closed by construction. A token that Apple
    /// did not produce fails the check unless someone rebuilt the whole
    /// attestation-object structure, and even then the SCP relay rejects it
    /// because it carries no Apple signature.
    enum AppAttestAttestationObject {
        /// The three keys an App Attest attestation object carries, and the only
        /// three `isWellFormed` accepts.
        private enum Key: String, CaseIterable {
            case format = "fmt"
            case attestationStatement = "attStmt"
            case authenticatorData = "authData"
        }

        /// The `fmt` value Apple writes into every App Attest attestation object.
        private static let appleAttestationFormat = "apple-appattest"

        /// The shortest authenticator data WebAuthn Level 2 §6.1 permits:
        /// a 32-byte RP ID hash, one flags byte, and a 4-byte signature counter.
        private static let minimumAuthenticatorDataLength = 37

        /// Report whether `token` satisfies the attestation-object criterion.
        ///
        /// - Parameter token: Raw bytes a caller received as an attestation.
        /// - Returns: `true` only for a complete, correctly keyed, definite-length
        ///   CBOR attestation object; `false` for empty input, truncated input,
        ///   trailing bytes, a wrong `fmt` value, a duplicated key, an unknown
        ///   key, a missing key, and authenticator data shorter than 37 bytes.
        static func isWellFormed(_ token: Data) -> Bool {
            var reader = CBORReader(token)
            guard let entryCount = reader.readMapHeader(),
                  entryCount == Key.allCases.count else { return false }

            // A map carrying `Key.allCases.count` entries, no key twice and no
            // key outside `Key`, carries each of the three keys exactly once.
            var seenKeys = Set<Key>()
            for _ in 0 ..< entryCount {
                guard let name = reader.readTextString(),
                      let key = Key(rawValue: name),
                      seenKeys.insert(key).inserted,
                      readValue(for: key, from: &reader) else { return false }
            }

            return reader.isAtEnd
        }

        /// Consume the value that follows `key` and report whether it satisfies
        /// the constraint that key imposes.
        private static func readValue(for key: Key, from reader: inout CBORReader) -> Bool {
            switch key {
            case .format:
                return reader.readTextString() == appleAttestationFormat
            case .attestationStatement:
                return reader.skipMap()
            case .authenticatorData:
                guard let length = reader.readByteStringLength() else { return false }
                return length >= minimumAuthenticatorDataLength
            }
        }
    }

    /// Reads the subset of CBOR (RFC 8949) that an App Attest attestation object
    /// uses: definite-length integers, byte strings, text strings, arrays, and
    /// maps.
    ///
    /// The reader rejects indefinite-length items, reserved additional-information
    /// values, tags, and floating-point items, because Apple emits none of them.
    /// Every read returns `nil` or `false` on malformed input; the reader never
    /// traps and never reads past the end of its buffer.
    private struct CBORReader {
        /// The deepest array or map nesting the reader will walk before it
        /// rejects the item. Apple's attestation object nests three levels
        /// (object → `attStmt` → `x5c` array), so this bound leaves headroom
        /// while it stops a crafted token from exhausting the stack.
        private static let maxNestingDepth = 16

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

        /// Read a definite-length byte string and report its length.
        mutating func readByteStringLength() -> Int? {
            guard let head = readHead(), head.major == 2 else { return nil }
            return consumePayload(count: head.argument)
        }

        /// Read a definite-length map head and report its entry count.
        ///
        /// Each entry costs at least two bytes, so a declared count larger than
        /// the remaining byte count cannot be satisfied and the reader rejects it
        /// without looping.
        mutating func readMapHeader() -> Int? {
            guard let head = readHead(), head.major == 5,
                  head.argument <= UInt64(remainingCount) else { return nil }
            return Int(head.argument)
        }

        /// Advance past one complete map, keys and values alike.
        mutating func skipMap() -> Bool {
            guard let entryCount = readMapHeader() else { return false }
            for _ in 0 ..< entryCount {
                guard skipValue(depth: 1) else { return false }
                guard skipValue(depth: 1) else { return false }
            }
            return true
        }

        /// Advance past one complete CBOR item.
        ///
        /// - Parameter depth: How many arrays or maps enclose this item.
        /// - Returns: `false` when the item truncates, uses a major type Apple
        ///   never emits, or nests deeper than `maxNestingDepth`.
        private mutating func skipValue(depth: Int) -> Bool {
            guard depth <= Self.maxNestingDepth else { return false }
            guard let head = readHead() else { return false }
            switch head.major {
            case 0, 1:
                // Unsigned and negative integers carry their whole value in the
                // head, so the reader already consumed them.
                return true
            case 2, 3:
                return consumePayload(count: head.argument) != nil
            case 4:
                return skipContainer(entryCount: head.argument, itemsPerEntry: 1, depth: depth)
            case 5:
                return skipContainer(entryCount: head.argument, itemsPerEntry: 2, depth: depth)
            default:
                // Major type 6 is a tag and major type 7 holds simple values and
                // floats. Apple emits neither inside an attestation object.
                return false
            }
        }

        /// Advance past the entries of one array or map.
        ///
        /// - Parameters:
        ///   - entryCount: The entry count the container's head declared.
        ///   - itemsPerEntry: 1 for an array element, 2 for a map key and value.
        ///   - depth: How many containers enclose this container.
        /// - Returns: `false` when the declared count exceeds the bytes that
        ///   remain, or when any enclosed item fails to parse.
        private mutating func skipContainer(
            entryCount: UInt64,
            itemsPerEntry: Int,
            depth: Int
        ) -> Bool {
            guard entryCount <= UInt64(remainingCount) else { return false }
            for _ in 0 ..< entryCount {
                for _ in 0 ..< itemsPerEntry {
                    guard skipValue(depth: depth + 1) else { return false }
                }
            }
            return true
        }
    }

#endif // os(iOS) || os(macOS)
