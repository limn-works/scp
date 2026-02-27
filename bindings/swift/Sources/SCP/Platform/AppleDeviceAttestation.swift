#if os(iOS) || os(macOS)

import CryptoKit
import DeviceCheck
import Foundation

// ---------------------------------------------------------------------------
// DeviceAttestationProvider protocol
//
// Mirrors the UniFFI callback interface `DeviceAttestationProvider` defined in
// `crates/scp-ffi/uniffi/src/lib.rs` (ADR-021, ADR-025). The generated Swift
// bindings will declare this protocol; this local definition is the source of
// truth until the XCFramework build pipeline is wired (SCP-103).
//
// Methods:
//   attest(challenge:deviceId:) -> Data   — generate hardware (or software)
//                                           attestation object bound to the
//                                           supplied challenge and device ID
//   assert(requestHash:)        -> Data   — generate a per-request assertion
//                                           using the stored App Attest key
// ---------------------------------------------------------------------------

/// Platform contract for device attestation.
///
/// Implemented by `AppleDeviceAttestation` and injected into the Rust engine
/// at SDK initialization via the UniFFI callback interface binding
/// (`DeviceAttestationProvider` in `scp.udl` / `lib.rs`). See ADR-021 and
/// ADR-025.
public protocol DeviceAttestationProvider: Sendable {
    /// Generate a device attestation token bound to `challenge` and
    /// `deviceId`.
    ///
    /// On hardware that supports App Attest the returned bytes are the
    /// CBOR-encoded Apple App Attest object from
    /// `DCAppAttestService.attestKey(_:clientDataHash:)`. On simulator or
    /// where App Attest is unavailable, a synthetic software-only token is
    /// returned.
    ///
    /// - Parameters:
    ///   - challenge: A server-issued random challenge (≥ 16 bytes). Included
    ///     in the `clientDataHash` so the attestation is bound to this
    ///     specific request.
    ///   - deviceId: A stable identifier for the device (e.g. the identity
    ///     DID UTF-8 bytes). Included in the `clientDataHash`.
    /// - Returns: Raw attestation bytes to be forwarded to the SCP relay for
    ///   server-side verification.
    /// - Throws: `AttestationError` on fatal failure (App Attest service
    ///   unreachable on a real device; should not throw on simulator).
    func attest(challenge: Data, deviceId: Data) async throws -> Data

    /// Generate a per-request assertion for a previously attested key.
    ///
    /// Called for every authenticated operation after the initial attestation.
    /// Wraps `DCAppAttestService.generateAssertion(_:clientData:)`.
    ///
    /// On simulator or where App Attest is unavailable, returns a synthetic
    /// assertion token.
    ///
    /// - Parameter requestHash: SHA-256 digest of the request payload to bind
    ///   this assertion to.
    /// - Returns: Raw assertion bytes to include in the request to the relay.
    /// - Throws: `AttestationError` on fatal failure.
    func assert(requestHash: Data) async throws -> Data
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by `AppleDeviceAttestation`.
public nonisolated enum AttestationError: Error, Sendable {
    /// The platform App Attest service returned an error.
    case serviceError(String)
    /// App Attest is not supported and no fallback was possible.
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
    /// Prefix for synthetic software-only attestation tokens.
    static let softwareTokenPrefix = "software-attestation-"
    /// Prefix for synthetic software-only assertion tokens.
    static let softwareAssertionPrefix = "software-assertion-"
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
///    where `clientDataHash = SHA-256(challenge || deviceId)`.
/// 3. `generateAssertion(_:clientData:)` — per-request proof of possession.
///
/// ## Software fallback (simulator / unavailable)
///
/// When `DCAppAttestService.shared.isSupported` is `false`, the adapter
/// returns a deterministic synthetic token and never throws. The caller
/// receives a valid-shaped but software-only token, allowing the protocol to
/// proceed in development and simulator environments.
///
/// ## Thread safety
///
/// `AppleDeviceAttestation` is `final` and conforms to `Sendable`. Internal
/// mutable state (`storedKeyId`) is protected by `NSLock`. All async methods
/// use `withCheckedThrowingContinuation` to bridge the completion-handler
/// APIs to structured concurrency.
///
/// See ADR-025 and `crates/scp-platform/src/traits.rs` `DeviceAttestation`.
public final class AppleDeviceAttestation: DeviceAttestationProvider, @unchecked Sendable {

    // `@unchecked Sendable` is justified: `storedKeyId` is a simple
    // Optional<String> protected by `lock`. No reference semantics escape.
    // See ADR-025 and .docs/standards/swift.md §Safety.

    private let service: DCAppAttestService
    private let defaults: UserDefaults
    private let lock: NSLock

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
        self.service = DCAppAttestService.shared
        self.defaults = UserDefaults.standard
        self.lock = NSLock()
    }

    /// Testing initializer that accepts injected dependencies.
    ///
    /// Used in unit tests to supply a mock `DCAppAttestService` subclass and
    /// an in-memory `UserDefaults` suite.
    init(service: DCAppAttestService, defaults: UserDefaults) {
        self.service = service
        self.defaults = defaults
        self.lock = NSLock()
    }

    // MARK: - DeviceAttestationProvider

    /// Generate an attestation token for the given challenge and device ID.
    ///
    /// On a real device with App Attest available:
    /// 1. Retrieves or generates the App Attest key ID.
    /// 2. Computes `clientDataHash = SHA-256(challenge || deviceId)`.
    /// 3. Calls `DCAppAttestService.attestKey(_:clientDataHash:)`.
    /// 4. Returns the raw CBOR attestation bytes.
    ///
    /// On simulator or when App Attest is unavailable:
    /// Returns a synthetic token of the form
    /// `"software-attestation-<UUID>"` (UTF-8 encoded).
    ///
    /// - Parameters:
    ///   - challenge: Server-issued random challenge bytes.
    ///   - deviceId: Stable device/identity identifier bytes.
    /// - Returns: Attestation token bytes.
    /// - Throws: `AttestationError.serviceError` if the App Attest service
    ///   returns an error on a real device.
    public func attest(challenge: Data, deviceId: Data) async throws -> Data {
        guard service.isSupported else {
            return softwareAttestationToken()
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
    /// On simulator or when App Attest is unavailable, returns a synthetic
    /// assertion of the form `"software-assertion-<UUID>"` (UTF-8 encoded).
    ///
    /// - Parameter requestHash: SHA-256 digest of the request payload.
    /// - Returns: Assertion bytes to include in the relay request.
    /// - Throws: `AttestationError.keyNotFound` if no key ID is stored
    ///   (i.e., `attest` was never called).
    ///   `AttestationError.serviceError` if the App Attest service fails.
    public func assert(requestHash: Data) async throws -> Data {
        guard service.isSupported else {
            return softwareAssertionToken()
        }

        guard let keyId = loadKeyId() else {
            throw AttestationError.keyNotFound
        }

        return try await withCheckedThrowingContinuation { continuation in
            service.generateAssertion(keyId, clientData: requestHash) { assertion, error in
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

    /// Perform client-side format validation of an attestation token.
    ///
    /// Full server-side verification is performed by the SCP relay, which
    /// calls Apple's App Attest attestation endpoint. This method is a
    /// lightweight sanity check only:
    /// - Hardware tokens: non-empty bytes.
    /// - Software tokens: UTF-8 string with `"software-attestation-"` prefix.
    ///
    /// - Parameter token: Raw attestation bytes to validate.
    /// - Returns: `true` if the token passes format validation.
    public func verify(token: Data) -> Bool {
        if token.isEmpty {
            return false
        }
        // Software-only tokens carry the known prefix; hardware tokens are
        // CBOR-encoded and will not start with this prefix.
        if let string = String(data: token, encoding: .utf8),
           string.hasPrefix(StorageKey.softwareTokenPrefix) {
            return true
        }
        // Non-empty non-software bytes are assumed valid for client-side
        // purposes; full verification is server-side.
        return true
    }

    // MARK: - Private helpers

    /// Retrieve the stored App Attest key ID, or generate and store a new one.
    ///
    /// Key generation is idempotent with respect to `UserDefaults`: if a key
    /// ID is already stored it is returned immediately without a round-trip to
    /// the App Attest service.
    ///
    /// - Returns: An App Attest key ID string suitable for use in
    ///   `attestKey(_:clientDataHash:)` and `generateAssertion(_:clientData:)`.
    /// - Throws: `AttestationError.serviceError` if `generateKey` fails.
    private func resolveKeyId() async throws -> String {
        if let existing = loadKeyId() {
            return existing
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

    /// Compute `SHA-256(challenge || deviceId)` for use as `clientDataHash`.
    ///
    /// Per ADR-025: `clientDataHash = SHA-256(challenge || deviceId)` where
    /// `||` is byte concatenation. This binds the attestation to both the
    /// server-issued challenge (replay prevention) and the device identity
    /// (device binding).
    ///
    /// - Parameters:
    ///   - challenge: Server-issued challenge bytes.
    ///   - deviceId: Device/identity identifier bytes.
    /// - Returns: 32-byte SHA-256 digest.
    private func computeClientDataHash(challenge: Data, deviceId: Data) -> Data {
        var combined = challenge
        combined.append(deviceId)
        return Data(SHA256.hash(data: combined))
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

    // MARK: Software fallback tokens

    /// Returns a synthetic software-only attestation token.
    ///
    /// Used when `DCAppAttestService.shared.isSupported == false` (simulator
    /// or devices without App Attest). The token is a UUID-suffixed string
    /// encoded as UTF-8 bytes. It is valid for client-side format checks but
    /// will be treated as `method: .softwareOnly` by the relay.
    ///
    /// - Returns: UTF-8-encoded synthetic attestation token.
    private func softwareAttestationToken() -> Data {
        let token = "\(StorageKey.softwareTokenPrefix)\(UUID().uuidString)"
        // Encoding cannot fail for a pure ASCII string.
        return token.data(using: .utf8) ?? Data(token.utf8)
    }

    /// Returns a synthetic software-only assertion token.
    ///
    /// Used when `DCAppAttestService.shared.isSupported == false` (simulator
    /// or devices without App Attest). The token is a UUID-suffixed string
    /// encoded as UTF-8 bytes.
    ///
    /// - Returns: UTF-8-encoded synthetic assertion token.
    private func softwareAssertionToken() -> Data {
        let token = "\(StorageKey.softwareAssertionPrefix)\(UUID().uuidString)"
        return token.data(using: .utf8) ?? Data(token.utf8)
    }
}

#endif // os(iOS) || os(macOS)
