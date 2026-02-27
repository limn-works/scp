import Foundation

// MARK: - IdentityHandle

/// Internal opaque handle wrapping the UniFFI-generated identity binding.
///
/// This placeholder mirrors the handle type that UniFFI will generate from
/// the Rust `Identity` opaque struct in `crates/scp-ffi/uniffi/src/bridge.rs`.
/// When the XCFramework build pipeline ships (SCP-103), this definition is
/// replaced by the auto-generated type in `Internal/ScpBindings.swift`.
///
/// `IdentityHandle` is `Sendable` because the underlying Rust handle is
/// `Send + Sync` (all SCP identity state is either immutable or internally
/// synchronized). The Swift side holds it as a value that crosses isolation
/// boundaries freely.
///
/// See ADR-021 for the UniFFI bridge design and ADR-026 for the Swift SDK
/// ergonomics layer.
internal final class IdentityHandle: Sendable {
    /// The DID string for this identity (e.g. `"did:dht:z6Mk..."`).
    let did: String
    /// The custody type used for key storage (e.g. `"platform"`, `"in_memory"`).
    let custodyType: String

    /// Creates an `IdentityHandle` with the given DID and custody type.
    ///
    /// - Parameters:
    ///   - did: The DID string.
    ///   - custodyType: The custody type string.
    init(did: String, custodyType: String) {
        self.did = did
        self.custodyType = custodyType
    }
}

// MARK: - UniFFI Bridge Stubs

/// Create a new identity via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `identity_create` function.
/// When the XCFramework ships (SCP-103), this free function is replaced by
/// the auto-generated binding. The completion handler pattern supports
/// `CheckedContinuation` bridging.
///
/// - Parameters:
///   - custody: The custody type string (e.g. `"platform"`, `"in_memory"`).
///   - completion: Callback delivering the created handle or an error.
internal func scpIdentityCreate(
    custody: String,
    completion: @Sendable @escaping (Result<IdentityHandle, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.identity(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-IDENTITY-001"
    )))
}

/// Load an existing identity via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `identity_load` function.
/// When the XCFramework ships (SCP-103), this free function is replaced by
/// the auto-generated binding.
///
/// - Parameters:
///   - did: The DID string to load.
///   - completion: Callback delivering the loaded handle or an error.
internal func scpIdentityLoad(
    did: String,
    completion: @Sendable @escaping (Result<IdentityHandle, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.identity(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-IDENTITY-002"
    )))
}

/// Rotate the signing key for an existing identity via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `identity_rotate_key` function.
/// When the XCFramework ships (SCP-103), this free function is replaced by
/// the auto-generated binding.
///
/// - Parameters:
///   - handle: The identity handle whose key should be rotated.
///   - completion: Callback delivering the updated handle or an error.
internal func scpIdentityRotateKey(
    handle: IdentityHandle,
    completion: @Sendable @escaping (Result<IdentityHandle, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.identity(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-IDENTITY-003"
    )))
}

// MARK: - Identity

/// An SCP identity backed by a DID (Decentralized Identifier).
///
/// `Identity` is the primary identity type in the Swift SDK. It wraps an
/// opaque ``IdentityHandle`` obtained from the UniFFI bridge layer and
/// exposes the DID string, custody type, and key rotation through a safe,
/// idiomatic Swift interface.
///
/// All factory methods and mutations are `async throws`, bridging the
/// asynchronous Rust FFI calls to Swift structured concurrency via
/// `CheckedContinuation`. The struct itself is `Sendable` and can be
/// passed freely across actor and task boundaries.
///
/// ## Usage
///
/// ```swift
/// let identity = try await Identity.create(custody: "platform")
/// print(identity.did)          // "did:dht:z6Mk..."
/// print(identity.custodyType)  // "platform"
///
/// let rotated = try await identity.rotateKey()
/// ```
///
/// ## Provenance
///
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - `.docs/scaffold/swift.md` §"SDK Type Definitions > Identity"
/// - Story SCP-099
public nonisolated struct Identity: Sendable {
    /// The DID string for this identity (e.g. `"did:dht:z6Mk..."`).
    public let did: String

    /// The custody type used for key storage (e.g. `"platform"`, `"in_memory"`).
    public let custodyType: String

    /// The internal handle wrapping the native UniFFI identity object.
    private let handle: IdentityHandle

    // MARK: - Internal Initializer

    /// Creates an `Identity` from an internal ``IdentityHandle``.
    ///
    /// This initializer is internal — callers should use ``create(custody:)``
    /// or ``load(did:)`` to obtain an `Identity`.
    ///
    /// - Parameter handle: The opaque identity handle from the UniFFI bridge.
    internal init(handle: IdentityHandle) {
        self.did = handle.did
        self.custodyType = handle.custodyType
        self.handle = handle
    }

    // MARK: - Factory Methods

    /// Create a new SCP identity with the specified key custody method.
    ///
    /// Generates a new Ed25519 signing keypair, registers a `did:dht` DID,
    /// and returns the resulting identity. The key material is stored
    /// according to the specified custody method.
    ///
    /// This method bridges the asynchronous UniFFI `identity_create` call
    /// to Swift concurrency via `CheckedContinuation`.
    ///
    /// - Parameter custody: Key custody type. `"platform"` (default) uses
    ///   platform-native secure storage (Apple Keychain on iOS/macOS);
    ///   `"in_memory"` uses an ephemeral in-memory key store suitable for
    ///   testing.
    /// - Returns: A new ``Identity`` instance.
    /// - Throws: ``ScpError/identity(message:code:)`` if key generation or
    ///   DID creation fails. ``ScpError/validation(message:code:)`` if
    ///   `custody` is not a recognised custody type.
    public static func create(custody: String = "platform") async throws -> Identity {
        let handle = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<IdentityHandle, Error>) in
            scpIdentityCreate(custody: custody) { result in
                switch result {
                case .success(let identityHandle):
                    continuation.resume(returning: identityHandle)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
        return Identity(handle: handle)
    }

    /// Load an existing identity from storage by its DID string.
    ///
    /// Retrieves the identity's key material from the custody provider
    /// and reconstitutes the identity object. The DID must have been
    /// previously created on this device or imported into the local
    /// key store.
    ///
    /// This method bridges the asynchronous UniFFI `identity_load` call
    /// to Swift concurrency via `CheckedContinuation`.
    ///
    /// - Parameter did: The DID string to load (e.g. `"did:dht:z6Mk..."`).
    /// - Returns: The loaded ``Identity`` instance.
    /// - Throws: ``ScpError/identity(message:code:)`` if the DID format is
    ///   unsupported or the identity cannot be found in storage.
    public static func load(did: String) async throws -> Identity {
        let handle = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<IdentityHandle, Error>) in
            scpIdentityLoad(did: did) { result in
                switch result {
                case .success(let identityHandle):
                    continuation.resume(returning: identityHandle)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
        return Identity(handle: handle)
    }

    // MARK: - Instance Methods

    /// Rotate this identity's active signing key.
    ///
    /// Generates a new Ed25519 signing key and updates the DID document.
    /// The DID string remains the same — only the active signing key
    /// changes (Layer 1 key rotation per §9 of the SCP specification).
    /// The previous key is retained in the DID document's key history
    /// for signature verification of historical messages.
    ///
    /// This method bridges the asynchronous UniFFI `identity_rotate_key`
    /// call to Swift concurrency via `CheckedContinuation`.
    ///
    /// - Returns: An updated ``Identity`` with the rotated signing key.
    ///   The ``did`` property is unchanged; only the underlying key
    ///   material and DID document are updated.
    /// - Throws: ``ScpError/identity(message:code:)`` if key rotation fails.
    ///   ``ScpError/crypto(message:code:)`` if the new key cannot be generated.
    public func rotateKey() async throws -> Identity {
        let handle = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<IdentityHandle, Error>) in
            scpIdentityRotateKey(handle: self.handle) { result in
                switch result {
                case .success(let newHandle):
                    continuation.resume(returning: newHandle)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
        return Identity(handle: handle)
    }
}
