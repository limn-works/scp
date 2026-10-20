import CryptoKit
import Foundation
import os
import Security

// MARK: - PlatformError

/// Errors thrown by the Apple platform key custody adapter.
///
/// Maps to the Rust `PlatformError` enum in `scp-platform/src/error.rs`.
/// All variants carry descriptive messages suitable for logging. Private key
/// material is never included in error messages.
///
/// See ADR-025 for the full Apple platform adapter design and ADR-006 for the
/// `KeyCustody` trait specification.
public nonisolated enum PlatformError: Error, Sendable {
    /// A Keychain operation failed. The associated `OSStatus` is the raw
    /// Security framework status code (e.g. `errSecDuplicateItem = -25299`).
    case keychainError(OSStatus)
    /// The key handle is not present in the Keychain. Either the handle is
    /// invalid or the key was previously destroyed.
    case keyNotFound(String)
    /// A cryptographic operation was attempted with a key of the wrong type.
    /// For example, calling `sign` with an HPKE P-256 handle or `dhAgree`
    /// with an Ed25519 handle.
    case wrongKeyType(String)
    /// Key destruction was initiated but the Keychain item persisted after
    /// deletion. The associated string is the key handle that could not be
    /// confirmed as destroyed.
    case destructionFailed(String)
    /// Biometric authentication failed or was cancelled by the user. The
    /// Keychain refused to release key material because the biometric check
    /// did not succeed.
    case biometricAuthenticationFailed(String)
    /// The Secure Enclave could not create a P-256 key on a host whose
    /// availability probe reported an enclave, for example because the
    /// process lacks the keychain entitlement
    /// (`errSecMissingEntitlement = -34018`). The associated `OSStatus` is the
    /// status `SecKeyCreateRandomKey` reported. The adapter never answers
    /// this failure with a software key: the backing is chosen once, from the
    /// probe, and an enclave host stays an enclave host (ADR-025 criterion 8).
    case secureEnclaveKeyCreationFailed(OSStatus)
    /// A P-256 mint failed after its key may have been created, and the
    /// rollback could not confirm that key gone. `keyId` names the key and
    /// its companion record, both of which remain; ``AppleKeyCustody/destroyKey(_:)``
    /// of `keyId` removes them. `cause` describes the failure that started
    /// the rollback.
    case mintRollbackIncomplete(keyId: String, cause: String)
    /// A general custody operation failed for reasons other than the variants
    /// above.
    case custodyError(String)
}

nonisolated extension PlatformError: LocalizedError {
    /// Human-readable error description. Safe for logging; no key material.
    public nonisolated var errorDescription: String? {
        switch self {
        case let .keychainError(status):
            "Keychain operation failed with OSStatus \(status)"
        case let .keyNotFound(handle):
            "Key not found for handle '\(handle)'"
        case let .wrongKeyType(detail):
            "Wrong key type: \(detail)"
        case let .destructionFailed(handle):
            "Key destruction failed: item persisted for handle '\(handle)'"
        case let .biometricAuthenticationFailed(detail):
            "Biometric authentication failed: \(detail)"
        case let .secureEnclaveKeyCreationFailed(status):
            "Secure Enclave key generation failed with OSStatus \(status); no software key is substituted"
        case let .mintRollbackIncomplete(keyId, cause):
            "Key generation failed (\(cause)) and key id '\(keyId)' could not be confirmed removed; destroy it"
        case let .custodyError(message):
            "Key custody error: \(message)"
        }
    }
}

// MARK: - KeyType

/// The cryptographic key type managed by ``AppleKeyCustody``.
///
/// Keys are tagged with their type at creation time so that subsequent
/// operations can enforce type safety (e.g. ``AppleKeyCustody/sign(_:data:)``
/// only accepts ``ed25519`` and ``p256`` handles). One key serves one
/// purpose: a signing key never agrees and an agreement key never signs.
///
/// See ADR-006 for the `KeyType` enum specification and ADR-025 for the Apple
/// platform adapter design.
public nonisolated enum KeyType: String, Sendable, Equatable {
    /// Ed25519 signing key. Used for identity keys and active signing keys.
    /// Private bytes are 32 bytes; public bytes are 32 bytes.
    case ed25519
    /// P-256 ECDSA signing key held by the Secure Enclave (spec 09 §9.5,
    /// ADR-025 criterion 8). Signs 32-byte digests; the public key is the
    /// 33-byte SEC1 compressed point.
    case p256
    /// P-256 key-agreement key held by the Secure Enclave, the HPKE
    /// DHKEM(P-256) wrapping key of spec 03 §3.7.2. Agrees only; the public
    /// key is the 65-byte SEC1 uncompressed point.
    case hpkeP256 = "hpke-p256"
}

// MARK: - BiometricPolicy

/// Controls whether biometric authentication (Face ID / Touch ID) is
/// required before the Keychain releases key material for signing and
/// key-agreement operations.
///
/// See ADR-025 Biometric gating for the design rationale and industry
/// comparison (Signal, WhatsApp).
public nonisolated enum BiometricPolicy: String, Sendable, Equatable {
    /// No biometric gate. Keys use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
    /// -- the default behavior. Background operations (relay connections, message
    /// processing) can access keys while the device is locked after first unlock.
    case none

    /// Biometric authentication (Face ID / Touch ID) is required every time
    /// `sign`, `dhAgree`, or `derivePseudonym` accesses key material. The
    /// Keychain item is created with `SecAccessControl` using
    /// `.biometryCurrentSet`, which ties access to the currently enrolled
    /// biometrics. If biometrics change (e.g., a new fingerprint is enrolled),
    /// existing keys become inaccessible -- triggering key rotation per 9.12.
    ///
    /// If the device has no biometric hardware, the system falls back to
    /// device passcode authentication.
    case required
}

// MARK: - DestructionAttestation

/// Attestation that a key has been destroyed.
///
/// Returned by ``AppleKeyCustody/destroyKey(_:)`` after successful deletion
/// and re-fetch confirmation. For Apple Keychain-backed keys, `method` is
/// always `.softwareOnly` because the key material lives in software (Keychain)
/// rather than a hardware security module.
///
/// See 9.15 of the SCP specification for key destruction requirements and
/// ADR-025 for the rationale behind software-only attestation on Apple platforms.
public nonisolated struct DestructionAttestation: Sendable {
    /// The destruction method. `.softwareOnly` for Keychain keys.
    public nonisolated let method: DestructionMethod
    /// `true` when the re-fetch after deletion confirmed `errSecItemNotFound`.
    public nonisolated let confirmed: Bool

    /// Memberwise initializer.
    public nonisolated init(method: DestructionMethod, confirmed: Bool) {
        self.method = method
        self.confirmed = confirmed
    }
}

/// The mechanism by which key material was destroyed.
///
/// See 9.15 of the SCP specification.
public nonisolated enum DestructionMethod: String, Sendable {
    /// Key material was deleted from software storage (e.g., Apple Keychain).
    /// No hardware destruction guarantee is available.
    case softwareOnly
    /// Key material was destroyed by the hardware security module. Not
    /// applicable to Apple Keychain-backed keys.
    case hardware
}

// MARK: - KeyMetadata

/// Internal metadata stored alongside a Keychain key item.
///
/// Encoded as a compact JSON blob and stored in `kSecAttrLabel`. This allows
/// type-checking, role reporting and public key retrieval without accessing
/// key material (which would trigger biometric prompts on gated keys).
nonisolated struct KeyMetadata: Codable {
    /// The ``KeyType`` of the stored key.
    let keyType: String
    /// Base64-encoded public key bytes in the form ``AppleKeyCustody/publicKey(_:)``
    /// returns (32 bytes for Ed25519, 33 for P-256, 65 for HPKE
    /// P-256), stored at generation time. `nil` for legacy items created
    /// before metadata caching was added, and for a P-256 key's companion
    /// item between its id reservation and the enclave key's creation.
    let publicKeyBase64: String?
    /// The ``KeyRole`` raw value the key was minted in. Required: an item
    /// without it fails to decode, so a role is never guessed.
    let role: String
    /// The custody string `custodyType(_:)` reports for the key, recorded at
    /// mint from where the key was created and the biometric policy it was
    /// created under: `"hardware"`, `"software"` or `"software_biometric"`.
    /// Required, so custody is never derived from the key type.
    let custodyType: String
    /// The ``P256Backing`` raw value of a P-256 or HPKE P-256 key, which
    /// selects the store every later operation on the key uses. `nil` for an
    /// Ed25519 key, whose private bytes the item itself holds.
    let backing: String?
    /// The ``AppleKeyCustody/currentProcessTag`` of the process minting a
    /// P-256 key, set on the reservation and cleared when the public key is
    /// recorded. ``AppleKeyCustody/sweepAbandonedMints(isAbandoned:)`` reads
    /// it to tell a crashed mint from a live one. `nil` on every settled key.
    let mintingProcess: String?

    /// This record with `publicKey` cached and the mint settled.
    func with(publicKey: Data) -> KeyMetadata {
        KeyMetadata(
            keyType: keyType,
            publicKeyBase64: publicKey.base64EncodedString(),
            role: role,
            custodyType: custodyType,
            backing: backing,
            mintingProcess: nil
        )
    }
}

/// The role a key was minted in, stored in ``KeyMetadata`` and reported as
/// the UniFFI `CustodyKeyRole` from `getPublicKey(keyId:)`.
private nonisolated enum KeyRole: String {
    case identity
    case operational

    init(_ role: CustodyKeyRole) {
        switch role {
        case .identity: self = .identity
        case .operational: self = .operational
        }
    }

    var custodyKeyRole: CustodyKeyRole {
        switch self {
        case .identity: .identity
        case .operational: .operational
        }
    }
}

// MARK: - AppleKeyCustody

/// Apple key custody provider: Ed25519 keys in the Keychain, and
/// P-256 signing and HPKE P-256 agreement keys in the Secure Enclave, or in
/// the platform signer where the host has no enclave.
///
/// The class conforms to the UniFFI `KeyCustodyProvider` callback interface
/// (`crates/scp-ffi/uniffi/src/lib.rs`), as ADR-025 requires, so an instance
/// passes directly to `identityCreateWithCustody(provider:)` and every other
/// bridge call that takes a provider. The `os_keystore` custody of spec 03
/// §3.2.2 reaches the Keychain through it with no caller glue.
///
/// ## Key ids
///
/// A key id is the canonical decimal form of a random `UInt64`, as
/// `String(n)` writes it, which is the only id shape the bridge accepts.
/// Generation adds the Keychain item without replacing an existing one and
/// draws a fresh id on `errSecDuplicateItem`, so a live key never shares an
/// id. An id that names a destroyed key is drawn again with probability
/// 2^-64 per earlier key.
///
/// ## Key storage
///
/// Each key has a `kSecClassGenericPassword` Keychain item:
/// - `kSecAttrService`: ``AppleKeyCustody/itemService``. Every query the
///   adapter runs carries it, so an item under another service is invisible
///   to it even when its account matches.
/// - `kSecAttrAccount`: `"scp.key.<id>"` where `<id>` is the key id.
/// - `kSecAttrLabel`: JSON-encoded ``KeyMetadata``: type, role, cached
///   public key, custody string and, for a P-256 key, its backing.
/// - `kSecAttrGeneric`: the public key bytes, so a key is found by its
///   public key with an exact-match query.
/// - `kSecAttrAccessGroup`: `"\(appIdentifierPrefix).dev.limn.scp"`.
/// - `kSecAttrAccessible`: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
/// - `kSecValueData`: for Ed25519, the 32-byte raw private key.
///   A P-256 key's item has no data.
///
/// A P-256 or HPKE P-256 key itself is a permanent `kSecClassKey` item
/// (``KeychainP256KeyStore``), tagged with the application tag
/// `"scp.key.<id>"` as `Data`. Its generic-password item, the companion,
/// exists because the generic-password class is the id registry:
/// `SecItemAdd` refuses a duplicate account, while `SecKeyCreateRandomKey`
/// accepts a duplicate tag. The companion also carries the key's type,
/// role, backing and custody string, which a key item has no attribute for.
/// No operation returns a P-256 private key's bytes.
///
/// ## Biometric gating
///
/// When initialized with ``BiometricPolicy/required``, key material is stored
/// with `SecAccessControl` requiring `.biometryCurrentSet` -- Face ID or Touch
/// ID must authenticate before `sign`, `dhAgree`, or `derivePseudonym` can
/// access the Keychain item. `publicKey` and `destroyKey` do NOT require
/// biometric authentication -- `publicKey` reads from metadata cache (attributes
/// only, no key material access), and `destroyKey` is a cleanup operation.
/// If the device has no biometric hardware, the system falls back to device
/// passcode. The policy applies to every key this instance mints, including
/// a P-256 key, whose access control then requires `.biometryCurrentSet`.
/// See ADR-025 Biometric gating.
///
/// ## P-256 keys
///
/// The initializer probes once for a Secure Enclave and fixes the
/// ``P256Backing`` every P-256 and HPKE P-256 key this instance mints uses:
/// - With an enclave, the enclave generates and holds each key (ADR-025
///   criterion 8), and the key's custody is `"hardware"`. A creation failure
///   is ``PlatformError/secureEnclaveKeyCreationFailed(_:)``; no software
///   key replaces it.
/// - Without one, the key is a permanent Security-framework key with no
///   token id, the platform signer of spec 09 §9.5, and its custody is
///   `"software"` (or `"software_biometric"` under
///   ``BiometricPolicy/required``).
///
/// The backing and custody are recorded in the companion at mint, and every
/// later operation reads them from there. A key signs digests with
/// `.ecdsaSignatureDigestX962SHA256` and agrees with
/// `.ecdhKeyExchangeStandard`. `sign` returns the store's DER signature; the
/// Rust bridge converts it to the 64-byte raw low-`s` form and verifies it
/// (spec 09 §9.5, ADR-025 criterion 1). Ed25519 keys stay in the Keychain
/// because neither store can hold them.
///
/// ## Thread safety
///
/// All Keychain operations are synchronous at the `Security.framework` level.
/// This class wraps them in `async` methods so callers can `await` them without
/// blocking a thread. Each operation creates and disposes its own Keychain
/// query dictionary; there is no shared mutable state beyond the Keychain itself.
///
/// ## Concurrency isolation
///
/// `AppleKeyCustody` runs its async operations `@concurrent` (off the main
/// actor) because Keychain I/O must not block the main thread. With Swift 6.2
/// approachable concurrency (`SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`),
/// using `@concurrent` is the correct way to force background execution.
///
/// See ADR-025 for the full design rationale and 9.15 for key destruction
/// requirements.
public final class AppleKeyCustody: Sendable {
    // MARK: - Configuration

    /// The Keychain access group for all SCP key items.
    ///
    /// The `$(AppIdentifierPrefix)` component (team ID prefix) is expanded at
    /// runtime from the app's provisioning profile. When running in unit-test
    /// or simulator contexts without a provisioning profile, pass an empty
    /// string or omit the access group to use the default keychain.
    private let accessGroup: String?

    /// The biometric authentication policy for key access operations.
    ///
    /// When `.required`, signing, key agreement, and pseudonym derivation
    /// operations require Face ID / Touch ID before the Keychain releases
    /// key material. When `.none`, keys use standard
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` protection with
    /// no biometric gate.
    ///
    /// See ADR-025 Biometric gating.
    let biometricPolicy: BiometricPolicy

    /// The backing of every P-256 and HPKE P-256 key this instance mints,
    /// fixed once from the enclave availability probe.
    let mintBacking: P256Backing

    /// The store of a backing. The public initializer builds a
    /// ``KeychainP256KeyStore``.
    private let makeP256Store: @Sendable (P256Backing) -> any P256KeyStore

    /// Draws a candidate key id.
    private let newKeyId: @Sendable () -> String

    /// Whether the process a pending reservation names is gone; see
    /// ``sweepAbandonedMints(isAbandoned:)``. The public initializer passes
    /// ``mintingProcessIsGone(_:)``.
    private let processIsGone: @Sendable (String) -> Bool

    // MARK: - Keychain item attribute helpers

    /// Returns the `kSecAttrAccount` value for a key handle.
    private nonisolated func account(for handle: String) -> String {
        Self.accountPrefix + handle
    }

    /// The `kSecAttrAccount` prefix every SCP key item carries.
    private nonisolated static let accountPrefix = "scp.key."

    /// The `kSecAttrService` of every generic-password item this adapter
    /// writes, and a term of every query it runs (see ``itemQuery()``).
    nonisolated static let itemService = "dev.limn.scp.key"

    /// The log a best-effort sweep reports an item it could not remove to.
    /// Messages name key ids and errors, never key material.
    private nonisolated static let log = Logger(subsystem: "dev.limn.scp", category: "AppleKeyCustody")

    // MARK: - Initialization

    /// Creates a new `AppleKeyCustody` instance.
    ///
    /// The instance probes once, with CryptoKit's `SecureEnclave.isAvailable`,
    /// for a Secure Enclave. With one, every P-256 and HPKE P-256 key it
    /// mints is an enclave key; without one, every such key is a
    /// Security-framework platform-signer key (spec 09 §9.5).
    ///
    /// - Parameters:
    ///   - accessGroup: The Keychain access group to use for all key
    ///     items. Pass `nil` to use the default Keychain (suitable for unit
    ///     tests and simulator). In production, pass
    ///     `"\(teamId).dev.limn.scp"` where `teamId` is the app's Apple Team ID
    ///     prefix (the `$(AppIdentifierPrefix)` build setting).
    ///   - biometricPolicy: Controls whether biometric authentication is
    ///     required before key access. Defaults to `.none` (no biometric gate),
    ///     preserving the existing behavior. Pass `.required` to gate signing,
    ///     key agreement, and pseudonym derivation behind Face ID / Touch ID.
    ///
    /// See ADR-025 for the access group rationale and Biometric gating for
    /// the biometric policy design.
    public convenience init(accessGroup: String? = nil, biometricPolicy: BiometricPolicy = .none) {
        self.init(
            accessGroup: accessGroup,
            biometricPolicy: biometricPolicy,
            enclaveAvailable: SecureEnclave.isAvailable,
            makeP256Store: { KeychainP256KeyStore(backing: $0, accessGroup: accessGroup) },
            newKeyId: { String(UInt64.random(in: .min ... .max)) }
        )
    }

    /// Creates an instance whose P-256 stores come from `makeP256Store`,
    /// whose candidate key ids come from `newKeyId`, and whose mints sweep
    /// the reservations `processIsGone` reports abandoned.
    ///
    /// Internal: the public initializer passes the real probe, the Keychain
    /// stores, random ids and ``mintingProcessIsGone(_:)``. Tests pass a
    /// store their unsigned test host can reach, a fixed probe result, an id
    /// source that records every id it hands out so cleanup and absence
    /// checks name exact ids, and a liveness check that marks only their own
    /// reservations abandoned, since every adapter in the test process
    /// shares one Keychain.
    init(
        accessGroup: String?,
        biometricPolicy: BiometricPolicy,
        enclaveAvailable: Bool,
        makeP256Store: @escaping @Sendable (P256Backing) -> any P256KeyStore,
        newKeyId: @escaping @Sendable () -> String,
        processIsGone: @escaping @Sendable (String) -> Bool = AppleKeyCustody.mintingProcessIsGone
    ) {
        self.accessGroup = accessGroup
        self.biometricPolicy = biometricPolicy
        mintBacking = enclaveAvailable ? .secureEnclave : .software
        self.makeP256Store = makeP256Store
        self.newKeyId = newKeyId
        self.processIsGone = processIsGone
    }

    // MARK: - Private Keychain helpers

    /// Builds a base Keychain query dictionary for a key handle.
    ///
    /// All operations (add, fetch, delete) start from this base and extend it
    /// with operation-specific keys.
    private nonisolated func baseQuery(for handle: String) -> [String: Any] {
        var query = itemQuery()
        query[kSecAttrAccount as String] = account(for: handle)
        return query
    }

    /// The class, service and access group every SCP key item is stored
    /// under. Every query starts here, so the service is never left out.
    private nonisolated func itemQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.itemService
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        return query
    }

    /// Decodes the ``KeyMetadata`` label from a Keychain attribute dictionary.
    private nonisolated static func metadata(from attrs: [String: Any]) -> KeyMetadata? {
        guard
            let labelString = attrs[kSecAttrLabel as String] as? String,
            let labelData = labelString.data(using: .utf8)
        else { return nil }
        return try? JSONDecoder().decode(KeyMetadata.self, from: labelData)
    }

    /// The ids of every key item this adapter holds whose cached public key
    /// is `publicKey`.
    ///
    /// Matches `kSecAttrGeneric`, which generation sets to the public key,
    /// so the Keychain answers an exact-match query instead of enumerating
    /// every item; an unfiltered `kSecMatchLimitAll` search on the macOS
    /// file keychain ends early when another thread deletes an item mid-scan.
    /// Each match is confirmed against the public key in its decoded
    /// ``KeyMetadata`` label. Reads attributes only, so a biometric-gated
    /// item raises no prompt.
    ///
    /// - Throws: ``PlatformError/keychainError(_:)`` for any Keychain failure
    ///   other than finding no items.
    nonisolated func keyIds(cachingPublicKey publicKey: Data) throws -> [String] {
        var query = itemQuery()
        query[kSecAttrGeneric as String] = publicKey as CFData
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            break
        case errSecItemNotFound:
            return []
        default:
            throw PlatformError.keychainError(status)
        }
        guard let items = result as? [[String: Any]] else {
            throw PlatformError.custodyError("Keychain returned no attribute list")
        }
        return items.compactMap { attrs in
            guard
                let account = attrs[kSecAttrAccount as String] as? String,
                account.hasPrefix(Self.accountPrefix),
                let cached = Self.metadata(from: attrs)?.publicKeyBase64,
                Data(base64Encoded: cached) == publicKey
            else { return nil }
            return String(account.dropFirst(Self.accountPrefix.count))
        }
    }

    /// Reads the ``KeyMetadata`` of the settled key `handle`.
    ///
    /// A P-256 reservation whose mint has not settled reads as absent:
    /// ``PlatformError/keyNotFound(_:)``, as for an id no item holds. Only
    /// ``destroyKey(_:)`` reads a pending record, through
    /// ``fetchRecord(for:)``.
    private nonisolated func fetchMetadata(for handle: String) throws -> KeyMetadata {
        let record = try fetchRecord(for: handle)
        guard !record.pending else { throw PlatformError.keyNotFound(handle) }
        return record.metadata
    }

    /// Reads the ``KeyMetadata`` of `handle` from Keychain attributes, settled
    /// or not, and whether it is a pending reservation: its companion carries
    /// ``pendingMintMarker`` or its record names a minting process.
    ///
    /// Reads `kSecReturnAttributes` only (NOT `kSecReturnData`), so this
    /// does NOT trigger biometric prompts on gated keys.
    private nonisolated func fetchRecord(for handle: String) throws -> (metadata: KeyMetadata, pending: Bool) {
        var query = baseQuery(for: handle)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard
                let attrs = result as? [String: Any],
                let metadata = Self.metadata(from: attrs)
            else {
                throw PlatformError.custodyError(
                    "Could not decode key metadata for handle '\(handle)'"
                )
            }
            let marked = attrs[kSecAttrComment as String] as? String == Self.pendingMintMarker
            return (metadata, marked || metadata.mintingProcess != nil)
        case errSecItemNotFound:
            throw PlatformError.keyNotFound(handle)
        default:
            throw PlatformError.keychainError(status)
        }
    }

    /// Reads the raw 32-byte private key bytes for `handle` from the Keychain.
    ///
    /// - Parameter handle: The key id returned by
    ///   ``generateKeypair(keyType:)``.
    /// - Returns: The raw private key bytes.
    /// - Throws: ``PlatformError/keyNotFound(_:)`` if the item does not exist,
    ///   ``PlatformError/biometricAuthenticationFailed(_:)`` if the user
    ///   cancelled the biometric prompt or authentication failed,
    ///   or ``PlatformError/keychainError(_:)`` for other Keychain failures.
    private nonisolated func fetchPrivateKeyBytes(for handle: String) throws -> Data {
        var query = baseQuery(for: handle)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw PlatformError.custodyError(
                    "Keychain returned unexpected data type for handle '\(handle)'"
                )
            }
            return data
        case errSecItemNotFound:
            throw PlatformError.keyNotFound(handle)
        case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
            throw PlatformError.biometricAuthenticationFailed(
                "Biometric authentication failed for handle '\(handle)' (OSStatus \(status))"
            )
        default:
            throw PlatformError.keychainError(status)
        }
    }

    /// Reads the ``KeyType``-tagged metadata label for `handle`.
    ///
    /// Delegates to ``fetchMetadata(for:)`` and extracts the key type.
    /// Does NOT trigger biometric prompts (reads attributes only).
    private nonisolated func fetchKeyType(for handle: String) throws -> KeyType {
        try Self.keyType(of: fetchMetadata(for: handle), handle: handle)
    }

    /// The ``KeyType`` a decoded record names.
    private nonisolated static func keyType(of metadata: KeyMetadata, handle: String) throws -> KeyType {
        guard let keyType = KeyType(rawValue: metadata.keyType) else {
            throw PlatformError.custodyError(
                "Unknown key type '\(metadata.keyType)' for handle '\(handle)'"
            )
        }
        return keyType
    }

    /// The store holding the P-256 key `metadata` records, chosen by the
    /// backing recorded at mint and never by the key type.
    private nonisolated func p256Store(for metadata: KeyMetadata, handle: String) throws -> any P256KeyStore {
        guard let raw = metadata.backing, let backing = P256Backing(rawValue: raw) else {
            throw PlatformError.custodyError(
                "Key id '\(handle)' records no P-256 backing (\(metadata.backing ?? "none"))"
            )
        }
        return makeP256Store(backing)
    }

    /// Reads the role `handle` was minted in from its metadata label.
    /// Does NOT trigger biometric prompts (reads attributes only).
    private nonisolated func fetchRole(for handle: String) throws -> KeyRole {
        let metadata = try fetchMetadata(for: handle)
        guard let role = KeyRole(rawValue: metadata.role) else {
            throw PlatformError.custodyError(
                "Unknown key role '\(metadata.role)' for handle '\(handle)'"
            )
        }
        return role
    }

    /// A `SecAccessControl` requiring the currently enrolled biometric set.
    /// `.biometryCurrentSet` invalidates access if biometrics change (new
    /// fingerprint enrolled, Face ID reset), which triggers key rotation per
    /// 9.12. Falls back to device passcode on hardware without biometric
    /// sensors.
    private nonisolated func biometricAccessControl(for handle: String) throws -> SecAccessControl {
        var cfError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &cfError
        ) else {
            let errorDesc = cfError.map { ($0.takeRetainedValue() as Error).localizedDescription }
                ?? "unknown error"
            throw PlatformError.custodyError(
                "Failed to create biometric access control for handle '\(handle)': \(errorDesc)"
            )
        }
        return accessControl
    }

    /// Stores 32-byte raw private key bytes in the Keychain under `handle`.
    ///
    /// The public key bytes are cached in the ``KeyMetadata`` label so that
    /// ``publicKey(_:)`` can return them without accessing key material
    /// (avoiding biometric prompts on gated keys).
    ///
    /// When ``biometricPolicy`` is `.required`, the item is stored with
    /// `SecAccessControl` requiring `.biometryCurrentSet`. When `.none`,
    /// the item uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
    ///
    /// An existing item under `handle` is replaced. Key generation does not
    /// use this method: it must never overwrite a key, so it adds through
    /// ``mintKey(keyType:role:)``.
    ///
    /// - Parameters:
    ///   - bytes: The raw 32-byte private key bytes.
    ///   - handle: The key id that will reference this key.
    ///   - keyType: The ``KeyType`` to tag this item with.
    ///   - role: The role to record for the key's lifetime.
    ///   - publicKeyBytes: The public key bytes to cache in metadata.
    /// - Throws: ``PlatformError/keychainError(_:)`` if the add operation fails.
    nonisolated func storePrivateKeyBytes(
        _ bytes: Data,
        for handle: String,
        keyType: KeyType,
        role: CustodyKeyRole,
        publicKeyBytes: Data
    ) throws {
        switch keyType {
        case .ed25519:
            break
        case .p256, .hpkeP256:
            throw PlatformError.wrongKeyType(
                "a \(keyType.rawValue) key lives in a P-256 key store and has no private bytes to store"
            )
        }
        let query = try addQuery(
            bytes, for: handle, keyType: keyType, role: role, publicKeyBytes: publicKeyBytes
        )
        let status = SecItemAdd(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            break
        case errSecDuplicateItem:
            try replaceExisting(handle: handle, query: query)
        default:
            throw PlatformError.keychainError(status)
        }
    }

    /// Builds the `SecItemAdd` query that stores `bytes` under `handle` with
    /// its metadata label and the access control of ``biometricPolicy``.
    private nonisolated func addQuery(
        _ bytes: Data,
        for handle: String,
        keyType: KeyType,
        role: CustodyKeyRole,
        publicKeyBytes: Data
    ) throws -> [String: Any] {
        var query = baseQuery(for: handle)
        query[kSecAttrLabel as String] = try metadataLabel(
            handle: handle,
            metadata: KeyMetadata(
                keyType: keyType.rawValue,
                publicKeyBase64: publicKeyBytes.base64EncodedString(),
                role: KeyRole(role).rawValue,
                custodyType: softwareCustodyType,
                backing: nil,
                mintingProcess: nil
            )
        )
        query[kSecAttrGeneric as String] = publicKeyBytes as CFData
        query[kSecValueData as String] = bytes as CFData

        switch biometricPolicy {
        case .none:
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        case .required:
            query[kSecAttrAccessControl as String] = try biometricAccessControl(for: handle)
        }
        return query
    }
}

// MARK: - Key minting

extension AppleKeyCustody {
    /// The number of fresh ids ``mintKey(keyType:role:)`` draws before it
    /// gives up. Eight collisions in a row among random 64-bit ids means the
    /// Keychain is not behaving as a store, not bad luck.
    private nonisolated static let mintAttempts = 8

    /// Generates a `keyType` keypair minted in `role` under a fresh random
    /// decimal `UInt64` id and returns that id.
    ///
    /// Every key, wherever its private half lives, has a generic-password
    /// item under `"scp.key.<id>"`, and that item is added first and never
    /// replaces an existing one: `errSecDuplicateItem` draws another id. The
    /// generic-password class is therefore the id registry for both item
    /// classes, so a live key is never overwritten and never shares its id.
    ///
    /// - Throws: ``PlatformError/keychainError(_:)`` if the add fails,
    ///   ``PlatformError/secureEnclaveKeyCreationFailed(_:)`` if the enclave
    ///   cannot create a P-256 key, ``PlatformError/custodyError(_:)`` if
    ///   every drawn id is taken.
    nonisolated func mintKey(keyType: KeyType, role: CustodyKeyRole) async throws -> String {
        switch keyType {
        case .ed25519:
            return try mintSoftwareKey(keyType: keyType, role: role)
        case .p256, .hpkeP256:
            return try await mintP256Key(keyType: keyType, role: role)
        }
    }

    /// The custody string of a key whose private bytes or software key this
    /// instance creates under ``biometricPolicy``.
    private nonisolated var softwareCustodyType: String {
        switch biometricPolicy {
        case .none: "software"
        case .required: "software_biometric"
        }
    }

    /// Mints an Ed25519 key whose 32 private bytes the Keychain item holds.
    private nonisolated func mintSoftwareKey(keyType: KeyType, role: CustodyKeyRole) throws -> String {
        var privateKeyBytes: Data
        let publicKeyBytes: Data
        switch keyType {
        case .ed25519:
            let signingKey = Curve25519.Signing.PrivateKey()
            privateKeyBytes = signingKey.rawRepresentation
            publicKeyBytes = signingKey.publicKey.rawRepresentation
        case .p256, .hpkeP256:
            throw PlatformError.wrongKeyType("a \(keyType.rawValue) key is not a Keychain software key")
        }
        defer { privateKeyBytes.resetBytes(in: 0 ..< privateKeyBytes.count) }

        for _ in 0 ..< Self.mintAttempts {
            let handle = newKeyId()
            let query = try addQuery(
                privateKeyBytes, for: handle, keyType: keyType, role: role, publicKeyBytes: publicKeyBytes
            )
            let status = SecItemAdd(query as CFDictionary, nil)
            switch status {
            case errSecSuccess:
                return handle
            case errSecDuplicateItem:
                continue
            default:
                throw PlatformError.keychainError(status)
            }
        }
        throw PlatformError.custodyError(
            "No free key id after \(Self.mintAttempts) draws"
        )
    }

    /// The application tag of the P-256 key under `handle`: the UTF-8 bytes
    /// of `"scp.key.<id>"`, as `Data` (`kSecAttrApplicationTag` is a data
    /// attribute).
    nonisolated func applicationTag(for handle: String) -> Data {
        Data(account(for: handle).utf8)
    }

    /// Mints a P-256 or HPKE P-256 key in the store of ``mintBacking``.
    ///
    /// 1. Reserves the id by adding the companion generic-password item,
    ///    which never replaces an existing item, recording the type, role,
    ///    backing and custody string.
    /// 2. Draws another id when a key item already carries the tag, since
    ///    `SecKeyCreateRandomKey` does not refuse a duplicate tag.
    /// 3. Creates the key, then records its public key on the companion.
    ///
    /// A failure after step 1 runs
    /// ``rollBackMint(handle:tag:store:cause:keyCreated:)`` and throws the
    /// error it returns: the original error when `create` itself threw or
    /// the key is confirmed gone, and
    /// ``PlatformError/mintRollbackIncomplete(keyId:cause:)`` when `create`
    /// returned a key the store cannot confirm deleted.
    ///
    /// A process that dies between step 1 and the end of step 3 leaves a
    /// reservation no caller can name. Before it reserves, every mint runs
    /// ``sweepAbandonedMints(isAbandoned:)`` with this instance's liveness
    /// check, which removes such reservations and their keys. The sweep is
    /// best-effort: it cannot fail the mint, and a reservation it cannot
    /// remove stays for a later sweep.
    private nonisolated func mintP256Key(keyType: KeyType, role: CustodyKeyRole) async throws -> String {
        await sweepAbandonedMints(isAbandoned: processIsGone)
        let store = makeP256Store(mintBacking)
        for _ in 0 ..< Self.mintAttempts {
            let handle = newKeyId()
            guard let reservation = try reserveP256(
                handle: handle, keyType: keyType, role: role, mintingProcess: Self.currentProcessTag
            ) else { continue }
            let tag = applicationTag(for: handle)
            guard try await tagIsFree(handle: handle, tag: tag, store: store) else { continue }
            var keyCreated = false
            do {
                let uncompressed = try await store.create(tag: tag, policy: biometricPolicy)
                keyCreated = true
                let publicKey = try Self.p256PublicKey(uncompressed, as: keyType)
                try recordCompanionPublicKey(
                    handle: handle, metadata: reservation.with(publicKey: publicKey), publicKey: publicKey
                )
                return handle
            } catch {
                throw await rollBackMint(
                    handle: handle, tag: tag, store: store, cause: error, keyCreated: keyCreated
                )
            }
        }
        throw PlatformError.custodyError(
            "No free key id after \(Self.mintAttempts) draws"
        )
    }

    /// Whether no key item carries `tag`. When one does, it is not this
    /// mint's: the reservation of `handle` is released and that item is left
    /// alone. A store failure also releases the reservation and propagates.
    private nonisolated func tagIsFree(handle: String, tag: Data, store: any P256KeyStore) async throws -> Bool {
        let taken: Bool
        do {
            taken = try await store.contains(tag: tag)
        } catch {
            try? deleteCompanion(handle: handle)
            throw error
        }
        if taken {
            try deleteCompanion(handle: handle)
        }
        return !taken
    }

    /// Removes what a failed P-256 mint added and returns the error the mint
    /// throws.
    ///
    /// The companion is the only record that names the key and its backing,
    /// so it is deleted only after the store reports no key under `tag`;
    /// otherwise it stays.
    ///
    /// The returned error is `cause` unchanged, keeping its type (for
    /// example ``PlatformError/secureEnclaveKeyCreationFailed(_:)``), unless
    /// `keyCreated` is true, meaning `create` returned and a key is known to
    /// exist, and the store cannot confirm that key deleted. Then the key may
    /// be permanent, and the error is
    /// ``PlatformError/mintRollbackIncomplete(keyId:cause:)`` naming
    /// `handle`: no caller learns the id of a failed mint any other way, and
    /// ``destroyKey(_:)`` of that id removes both.
    private nonisolated func rollBackMint(
        handle: String, tag: Data, store: any P256KeyStore, cause: Error, keyCreated: Bool
    ) async -> Error {
        _ = try? await store.delete(tag: tag)
        guard (try? await store.contains(tag: tag)) == false else {
            guard keyCreated else { return cause }
            return PlatformError.mintRollbackIncomplete(keyId: handle, cause: cause.localizedDescription)
        }
        try? deleteCompanion(handle: handle)
        return cause
    }

    /// The public key `publicKey(_:)` returns for a `keyType` key whose
    /// uncompressed point is `uncompressed`: the 65 bytes for HPKE P-256,
    /// the 33-byte compressed point for P-256.
    nonisolated static func p256PublicKey(_ uncompressed: Data, as keyType: KeyType) throws -> Data {
        switch keyType {
        case .hpkeP256:
            guard uncompressed.count == 65, uncompressed.first == 0x04 else {
                throw PlatformError.custodyError(
                    "HPKE P-256 public key is \(uncompressed.count) bytes, expected 65 uncompressed"
                )
            }
            return uncompressed
        case .p256:
            do {
                return try P256.Signing.PublicKey(x963Representation: uncompressed).compressedRepresentation
            } catch {
                throw PlatformError.custodyError("P-256 public key is not a valid point: \(error.localizedDescription)")
            }
        case .ed25519:
            throw PlatformError.wrongKeyType("a \(keyType.rawValue) key has no P-256 public key")
        }
    }

    /// Encodes `metadata` as the `kSecAttrLabel` of the item of `handle`;
    /// the one encoder every item's label goes through.
    private nonisolated func metadataLabel(handle: String, metadata: KeyMetadata) throws -> String {
        guard
            let data = try? JSONEncoder().encode(metadata),
            let label = String(data: data, encoding: .utf8)
        else {
            throw PlatformError.custodyError("Failed to encode key metadata for handle '\(handle)'")
        }
        return label
    }

    /// The record that reserves an id for a `keyType` key minted in `role`
    /// in the store of ``mintBacking`` by `mintingProcess`.
    private nonisolated func p256Reservation(
        keyType: KeyType, role: CustodyKeyRole, mintingProcess: String
    ) -> KeyMetadata {
        let custody = switch mintBacking {
        case .secureEnclave: "hardware"
        case .software: softwareCustodyType
        }
        return KeyMetadata(
            keyType: keyType.rawValue,
            publicKeyBase64: nil,
            role: KeyRole(role).rawValue,
            custodyType: custody,
            backing: mintBacking.rawValue,
            mintingProcess: mintingProcess
        )
    }

    /// Reserves `handle` for a `keyType` key minted in `role` by
    /// `mintingProcess`, and returns the reservation's record, or `nil` when
    /// an item already holds the id.
    ///
    /// ``mintP256Key(keyType:role:)`` reserves through it. Internal so a test
    /// can leave the reservation a crashed mint leaves.
    nonisolated func reserveP256(
        handle: String, keyType: KeyType, role: CustodyKeyRole, mintingProcess: String
    ) throws -> KeyMetadata? {
        let reservation = p256Reservation(keyType: keyType, role: role, mintingProcess: mintingProcess)
        return try reserveCompanion(handle: handle, metadata: reservation) ? reservation : nil
    }

    /// The `kSecAttrComment` of a companion whose mint has not settled. An
    /// exact-match query on it finds every unsettled reservation without
    /// enumerating the Keychain (see ``keyIds(cachingPublicKey:)``).
    private nonisolated static let pendingMintMarker = "scp.mint.pending"

    /// Adds the companion item that reserves `handle` for a P-256 key,
    /// marked with ``pendingMintMarker``. Returns `false` when an item
    /// already holds the id. The item carries no secret, so it is readable
    /// after first unlock whatever the biometric policy; the P-256 key
    /// itself carries the policy.
    private nonisolated func reserveCompanion(handle: String, metadata: KeyMetadata) throws -> Bool {
        var query = baseQuery(for: handle)
        query[kSecAttrLabel as String] = try metadataLabel(handle: handle, metadata: metadata)
        query[kSecAttrComment as String] = Self.pendingMintMarker
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return true
        case errSecDuplicateItem:
            return false
        default:
            throw PlatformError.keychainError(status)
        }
    }

    /// Records the created key's public key on its companion item: the
    /// label's cached copy and `kSecAttrGeneric` for lookup by public key.
    /// The same update clears ``pendingMintMarker``, so a settled key is
    /// never a sweep candidate.
    private nonisolated func recordCompanionPublicKey(
        handle: String, metadata: KeyMetadata, publicKey: Data
    ) throws {
        let update: [String: Any] = try [
            kSecAttrLabel as String: metadataLabel(handle: handle, metadata: metadata),
            kSecAttrGeneric as String: publicKey as CFData,
            kSecAttrComment as String: ""
        ]
        let status = SecItemUpdate(baseQuery(for: handle) as CFDictionary, update as CFDictionary)
        guard status == errSecSuccess else {
            throw PlatformError.keychainError(status)
        }
    }

    /// Deletes the companion item of `handle`; an absent item is not an
    /// error.
    private nonisolated func deleteCompanion(handle: String) throws {
        let status = SecItemDelete(baseQuery(for: handle) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PlatformError.keychainError(status)
        }
    }

    /// A pending P-256 reservation whose minting process is gone: its id
    /// and the backing its record names.
    struct AbandonedMint: Equatable {
        let handle: String
        let backing: P256Backing
    }

    /// Removes every P-256 reservation whose minting process `isAbandoned`
    /// reports gone, with any key under its tag, and returns the ids removed.
    ///
    /// Best-effort, and never fails its caller: a scan that cannot list the
    /// reservations, or a reservation that cannot be removed, is logged
    /// without key material and left in place for a later sweep. No
    /// guarantee of spec 09 §9.15 depends on the sweep; an abandoned
    /// reservation reads as absent (``fetchMetadata(for:)``).
    @discardableResult
    nonisolated func sweepAbandonedMints(isAbandoned: (String) -> Bool) async -> [String] {
        let items: [[String: Any]]
        do {
            items = try pendingReservations()
        } catch {
            Self.log.warning(
                "Abandoned P-256 mints could not be listed: \(String(describing: error), privacy: .public)"
            )
            return []
        }
        return await sweep(Self.abandonedMints(in: items, isAbandoned: isAbandoned))
    }

    /// Removes each of `mints`, key first, and returns the ids removed.
    ///
    /// The key is deleted from the store its record names and confirmed gone
    /// before the companion is deleted, so a key is never left without a
    /// record. A mint that cannot be removed is logged and keeps its
    /// reservation.
    nonisolated func sweep(_ mints: [AbandonedMint]) async -> [String] {
        var swept: [String] = []
        for mint in mints {
            do {
                let tag = applicationTag(for: mint.handle)
                let store = makeP256Store(mint.backing)
                if try await store.contains(tag: tag) {
                    _ = try await deleteConfirmed(mint.handle, tag: tag, from: store)
                }
                try deleteCompanion(handle: mint.handle)
                swept.append(mint.handle)
            } catch {
                Self.log.warning("""
                Abandoned P-256 mint \(mint.handle, privacy: .public) could not be swept and stays \
                reserved: \(String(describing: error), privacy: .public)
                """)
            }
        }
        return swept
    }

    /// The abandoned mints among `items`, the attribute dictionaries of
    /// generic-password items.
    ///
    /// An item is one only when it carries ``itemService`` and
    /// ``pendingMintMarker``, its account has the key prefix, its record
    /// decodes with a P-256 type and backing, no public key is recorded, it
    /// names a minting process, and `isAbandoned` reports that process gone.
    /// Any other item is left alone.
    nonisolated static func abandonedMints(
        in items: [[String: Any]], isAbandoned: (String) -> Bool
    ) -> [AbandonedMint] {
        items.compactMap { attrs in
            guard
                attrs[kSecAttrService as String] as? String == itemService,
                attrs[kSecAttrComment as String] as? String == pendingMintMarker,
                let account = attrs[kSecAttrAccount as String] as? String,
                account.hasPrefix(accountPrefix),
                let metadata = metadata(from: attrs),
                metadata.publicKeyBase64 == nil,
                let process = metadata.mintingProcess,
                let backing = metadata.backing.flatMap(P256Backing.init(rawValue:)),
                KeyType(rawValue: metadata.keyType).map({ $0 == .p256 || $0 == .hpkeP256 }) == true,
                isAbandoned(process)
            else { return nil }
            return AbandonedMint(handle: String(account.dropFirst(accountPrefix.count)), backing: backing)
        }
    }

    /// The attributes of every companion carrying ``pendingMintMarker``.
    ///
    /// The macOS file keychain fails a multi-item query with
    /// `errSecInvalidRecord` when another thread updates or deletes a
    /// matching item mid-scan, as a concurrent mint settling or rolling back
    /// its reservation does. That status ends the scan with no items: a
    /// reservation it missed stays as it was, and a later sweep finds it.
    ///
    /// - Throws: ``PlatformError/keychainError(_:)`` for any other failure.
    private nonisolated func pendingReservations() throws -> [[String: Any]] {
        var query = itemQuery()
        query[kSecAttrComment as String] = Self.pendingMintMarker
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let items = result as? [[String: Any]] else {
                throw PlatformError.custodyError("Keychain returned no attributes for pending mints")
            }
            return items
        case errSecItemNotFound, errSecInvalidRecord:
            return []
        default:
            throw PlatformError.keychainError(status)
        }
    }

    /// The tag ``KeyMetadata/mintingProcess`` records for this process:
    /// `"<pid>:<start seconds>.<start microseconds>"`. The start time tells
    /// this process from a later one that reuses its pid.
    nonisolated static let currentProcessTag: String = {
        let pid = getpid()
        guard let start = processStartTime(pid) else { return "\(pid):unknown" }
        return "\(pid):\(start)"
    }()

    /// The start time of process `pid` as `"<seconds>.<microseconds>"`, or
    /// `nil` when the kernel does not report it: no such process, or one this
    /// process may not inspect.
    nonisolated static func processStartTime(_ pid: pid_t) -> String? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0, size > 0 else { return nil }
        let start = info.kp_proc.p_un.__p_starttime
        return "\(start.tv_sec).\(start.tv_usec)"
    }

    /// Whether the process `tag` names is gone: its pid has no process, or
    /// the process under that pid started at another time. Fails toward
    /// alive: this process's own tag, a malformed tag, an unknown start time,
    /// a pid the kernel will not describe and any other doubt all report
    /// `false`, so a live mint is never swept.
    nonisolated static func mintingProcessIsGone(_ tag: String) -> Bool {
        guard tag != currentProcessTag else { return false }
        let parts = tag.split(separator: ":", maxSplits: 1).map(String.init)
        guard parts.count == 2, let pid = pid_t(parts[0]), pid > 0, parts[1] != "unknown" else { return false }
        if kill(pid, 0) == -1, errno == ESRCH {
            return true
        }
        guard let start = processStartTime(pid) else { return false }
        return start != parts[1]
    }

    /// Whether the generic-password item of `handle` is gone.
    private nonisolated func companionAbsent(handle: String) -> Bool {
        var query = baseQuery(for: handle)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecItemNotFound
    }

    /// Resolves an `errSecDuplicateItem` from storing `query` under `handle`:
    /// the existing item is replaced, so the new bytes and the current
    /// biometric policy apply.
    private nonisolated func replaceExisting(
        handle: String,
        query: [String: Any]
    ) throws {
        let deleteStatus = SecItemDelete(baseQuery(for: handle) as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw PlatformError.keychainError(deleteStatus)
        }
        let retryStatus = SecItemAdd(query as CFDictionary, nil)
        guard retryStatus == errSecSuccess else {
            throw PlatformError.keychainError(retryStatus)
        }
    }
}

// MARK: - Software key operations

extension AppleKeyCustody {
    /// Signs `data` with the Ed25519 key `keyHandle`, whose type the caller
    /// has checked, and wipes the local copy of its private bytes.
    nonisolated func signEd25519(_ keyHandle: String, data: Data) throws -> Data {
        var privateKeyBytes = try fetchPrivateKeyBytes(for: keyHandle)
        defer { privateKeyBytes.resetBytes(in: 0 ..< privateKeyBytes.count) }

        do {
            let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
            return try signingKey.signature(for: data)
        } catch let platformErr as PlatformError {
            throw platformErr
        } catch {
            throw PlatformError.custodyError(
                "Ed25519 signing failed for handle '\(keyHandle)': \(error.localizedDescription)"
            )
        }
    }

    /// P-256 ECDH with the HPKE P-256 key `keyHandle`, whose record the
    /// caller has read and type-checked, inside the store that record names.
    ///
    /// The peer is parsed with CryptoKit first, which rejects a point that
    /// is not on the curve, so an invalid point never reaches the store.
    private nonisolated func agreeP256(_ keyHandle: String, metadata: KeyMetadata, peerPublic: Data) async throws -> Data {
        guard peerPublic.count == 65 else {
            throw PlatformError.custodyError(
                "HPKE P-256 peer must be a 65-byte uncompressed point; got \(peerPublic.count) bytes"
            )
        }
        let peer: P256.KeyAgreement.PublicKey
        do {
            peer = try P256.KeyAgreement.PublicKey(x963Representation: peerPublic)
        } catch {
            throw PlatformError.custodyError(
                "HPKE P-256 peer is not a point on the curve: \(error.localizedDescription)"
            )
        }
        let secret = try await p256Store(for: metadata, handle: keyHandle).agree(
            tag: applicationTag(for: keyHandle), peer: peer.x963Representation
        )
        guard secret.count == 32 else {
            throw PlatformError.custodyError(
                "P-256 ECDH returned \(secret.count) bytes, expected 32"
            )
        }
        return secret
    }
}

// MARK: - Pseudonym derivation

extension AppleKeyCustody {
    /// Shared §9.10.4.A derivation: reads the Ed25519 seed of
    /// `identityHandle` and returns the 33-byte compressed pseudonym point
    /// computed by the shared Rust helper. `epoch` is `nil` for the v1
    /// (static) pseudonym. Nothing is stored: a pseudonym has no private key
    /// after this call, so destroying the identity leaves nothing to derive
    /// from.
    nonisolated func derivePseudonymPoint(
        method: String,
        identityHandle: String,
        contextId: Data,
        epoch: UInt64?
    ) throws -> Data {
        let storedType = try fetchKeyType(for: identityHandle)
        switch storedType {
        case .ed25519:
            break
        case .p256, .hpkeP256:
            throw PlatformError.wrongKeyType(
                "\(method) requires an Ed25519 key; handle '\(identityHandle)' is \(storedType.rawValue)"
            )
        }

        var identitySeed = try fetchPrivateKeyBytes(for: identityHandle)
        defer { identitySeed.resetBytes(in: 0 ..< identitySeed.count) }

        do {
            return try p256SoftwarePseudonymPoint(ikm: identitySeed, contextId: contextId, epoch: epoch)
        } catch let scpErr as ScpError {
            // The shared helper's typed error and code reach the caller
            // unchanged, as in the Kotlin SDK.
            throw scpErr
        } catch {
            throw PlatformError.custodyError(
                "P-256 pseudonym derivation failed: \(error.localizedDescription)"
            )
        }
    }
}

// MARK: - Key custody operations

public extension AppleKeyCustody {
    // MARK: generateKeypair

    /// Generates a keypair of `keyType`: an Ed25519 key whose private bytes
    /// the Apple Keychain holds, or a P-256 or HPKE P-256 key
    /// the Secure Enclave or, on a host without one, the platform signer
    /// generates and holds.
    ///
    /// Ed25519 private key bytes are stored as a
    /// `kSecClassGenericPassword` item.
    /// When ``biometricPolicy`` is `.none`, the item uses
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, ensuring background
    /// operations can access keys while the device is locked. When `.required`,
    /// the item uses `SecAccessControl` with `.biometryCurrentSet`. The key
    /// never leaves the Keychain after generation; all operations retrieve
    /// it on demand and operate in-process.
    ///
    /// The key is minted in the operational role. An identity key comes from
    /// the bridge through `generateKeypair(keyType:role:)`, which records the
    /// role the bridge names.
    ///
    /// - Parameter keyType: `"ed25519"`, `"p256"` or `"hpke-p256"`.
    /// - Returns: The key id, a canonical decimal `UInt64` string. Pass this
    ///   to other methods on this instance to perform operations with the key.
    /// - Throws: ``PlatformError/keychainError(_:)`` if the Keychain add fails,
    ///   ``PlatformError/secureEnclaveKeyCreationFailed(_:)`` if the Secure
    ///   Enclave cannot create a P-256 key (no software key replaces it),
    ///   ``PlatformError/custodyError(_:)`` for an unknown `keyType` string.
    ///
    /// See ADR-025 Key custody and ADR-006 `generate_keypair`.
    @concurrent
    func generateKeypair(keyType: String) async throws -> String {
        guard let parsedType = KeyType(rawValue: keyType) else {
            throw PlatformError.custodyError("Unknown key type '\(keyType)'")
        }
        return try await mintKey(keyType: parsedType, role: .operational)
    }

    // MARK: sign

    /// Signs `data` with the Ed25519 or P-256 key identified by `keyHandle`.
    ///
    /// - An Ed25519 key signs `data` and returns the 64-byte Ed25519
    ///   signature. Its private key bytes are held in memory only for the
    ///   duration of this call; they are not cached, logged, or returned
    ///   across the FFI boundary.
    /// - A P-256 key signs the 32-byte digest `data` in the store its record
    ///   names (`.ecdsaSignatureDigestX962SHA256`, no second hash) and
    ///   returns the store's DER `ECDSA-Sig-Value`. The Rust bridge converts
    ///   it to the 64-byte raw `r || s` with `s` in the low half of the group
    ///   order and verifies it (spec 09 §9.5, ADR-025 criterion 1).
    ///
    /// - Parameters:
    ///   - keyHandle: The key id of an `"ed25519"` or `"p256"` key.
    ///   - data: The bytes to sign; a 32-byte digest for a P-256 key.
    /// - Returns: A 64-byte Ed25519 signature, or a P-256 DER signature.
    /// - Throws: ``PlatformError/wrongKeyType(_:)`` if `keyHandle` refers to
    ///   an HPKE P-256 key, ``PlatformError/keyNotFound(_:)`` if the
    ///   handle is unknown, ``PlatformError/biometricAuthenticationFailed(_:)``
    ///   if biometric gating is active and authentication fails,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` if CryptoKit rejects Ed25519 key
    ///   bytes, a P-256 digest is not 32 bytes or the store fails.
    ///
    /// See ADR-025 Key custody and ADR-006 `sign`.
    @concurrent
    func sign(_ keyHandle: String, data: Data) async throws -> Data {
        let metadata = try fetchMetadata(for: keyHandle)
        let storedType = try Self.keyType(of: metadata, handle: keyHandle)
        switch storedType {
        case .ed25519:
            return try signEd25519(keyHandle, data: data)
        case .p256:
            guard data.count == 32 else {
                throw PlatformError.custodyError(
                    "P-256 sign takes a 32-byte digest; got \(data.count) bytes"
                )
            }
            return try await p256Store(for: metadata, handle: keyHandle)
                .sign(tag: applicationTag(for: keyHandle), digest: data)
        case .hpkeP256:
            throw PlatformError.wrongKeyType(
                "sign requires an Ed25519 or P-256 key; handle '\(keyHandle)' is \(storedType.rawValue)"
            )
        }
    }

    // MARK: publicKey

    /// Returns the public key for any key handle: 32 bytes for Ed25519, the
    /// 33-byte SEC1 compressed point for P-256, and the 65-byte
    /// SEC1 uncompressed point for HPKE P-256.
    ///
    /// Reads the cached public key from Keychain metadata attributes. This
    /// does NOT access key material and therefore does NOT trigger biometric
    /// prompts on gated keys. Without a cached copy of the expected length,
    /// an Ed25519 key derives it from its private bytes (legacy
    /// items that predate the metadata cache) and a P-256 key reads it from
    /// the store its record names.
    ///
    /// - Parameter keyHandle: The key id returned by
    ///   ``generateKeypair(keyType:)``.
    /// - Returns: The raw public key bytes.
    /// - Throws: ``PlatformError/keyNotFound(_:)`` if the handle is unknown,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` if the stored key type is unknown
    ///   or CryptoKit rejects Ed25519 key bytes.
    ///
    /// See ADR-025 Key custody and ADR-006 `public_key`.
    @concurrent
    func publicKey(_ keyHandle: String) async throws -> Data {
        let metadata = try fetchMetadata(for: keyHandle)
        guard let keyType = KeyType(rawValue: metadata.keyType) else {
            throw PlatformError.custodyError(
                "Unknown key type '\(metadata.keyType)' for handle '\(keyHandle)'"
            )
        }

        // Read from metadata cache (attributes only -- no biometric prompt).
        let expectedLength = switch keyType {
        case .ed25519: 32
        case .p256: 33
        case .hpkeP256: 65
        }
        if let pubKeyBase64 = metadata.publicKeyBase64,
           let pubKeyData = Data(base64Encoded: pubKeyBase64),
           pubKeyData.count == expectedLength {
            return pubKeyData
        }

        switch keyType {
        case .ed25519:
            return try legacyPublicKey(keyHandle) { privateKeyBytes in
                try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyBytes).publicKey.rawRepresentation
            }
        case .p256, .hpkeP256:
            let uncompressed = try await p256Store(for: metadata, handle: keyHandle)
                .publicKey(tag: applicationTag(for: keyHandle))
            return try Self.p256PublicKey(uncompressed, as: keyType)
        }
    }

    /// Derives an Ed25519 public key from the private bytes of a
    /// legacy item stored before metadata caching. Reading the bytes WILL
    /// trigger a biometric prompt if the item is gated.
    private nonisolated func legacyPublicKey(
        _ keyHandle: String,
        derive: (Data) throws -> Data
    ) throws -> Data {
        var privateKeyBytes = try fetchPrivateKeyBytes(for: keyHandle)
        defer { privateKeyBytes.resetBytes(in: 0 ..< privateKeyBytes.count) }
        do {
            return try derive(privateKeyBytes)
        } catch {
            throw PlatformError.custodyError(
                "Public key derivation failed for handle '\(keyHandle)': \(error.localizedDescription)"
            )
        }
    }

    // MARK: destroyKey

    /// Deletes the key `keyHandle` names and returns a destruction
    /// attestation after confirming that it no longer exists. No pseudonym
    /// item exists to delete: a pseudonym is a public point derived on
    /// demand from the identity seed, so once the seed is gone no pseudonym
    /// of this identity can be derived again (§9.10.4.A).
    ///
    /// ## Deletion verification
    ///
    /// An Ed25519 key is its generic-password item. A P-256 or
    /// HPKE P-256 key is a key item in the store its companion records plus
    /// that companion; the key item is deleted first, so a failure part-way
    /// leaves the record of a key that is gone, never a key without a record.
    /// When the companion is missing, does not decode, or records a key type
    /// this adapter does not know (a retired one such as `"x25519"`), the
    /// store of ``mintBacking`` is still asked for a key under the id's tag,
    /// an orphaned key is deleted, and the companion item is deleted: the
    /// custody contract destroys whatever the id names, whatever its type. After each delete this method re-fetches, and
    /// if the re-fetch finds the item it throws
    /// ``PlatformError/destructionFailed(_:)``.
    ///
    /// ## Attestation
    ///
    /// Returns a ``DestructionAttestation`` with `method: .softwareOnly` and
    /// `confirmed: true`. The `.softwareOnly` method reflects that this
    /// adapter observes only the Keychain deletion (ADR-025 criterion 9,
    /// §9.15): for an enclave key, deleting the reference discards the key,
    /// but the enclave issues no proof of it.
    ///
    /// - Parameter keyHandle: The key id returned by
    ///   ``generateKeypair(keyType:)``.
    /// - Returns: A ``DestructionAttestation`` confirming software deletion.
    /// - Throws: ``PlatformError/keyNotFound(_:)`` if neither a companion nor
    ///   a key item exists, ``PlatformError/destructionFailed(_:)`` if an
    ///   item persists after deletion, ``PlatformError/keychainError(_:)`` for
    ///   other Keychain failures.
    ///
    /// See ADR-025 Key destruction attestation and 9.15.
    @concurrent
    @discardableResult
    func destroyKey(_ keyHandle: String) async throws -> DestructionAttestation {
        // A missing or undecodable companion, or one recording a type this
        // adapter does not know, gives no usable type or backing, so the store
        // this instance mints into is asked for an orphaned key and the
        // companion is deleted below; a store failure propagates and nothing
        // is reported destroyed.
        let metadata: KeyMetadata?
        do {
            metadata = try fetchRecord(for: keyHandle).metadata
        } catch PlatformError.keyNotFound, PlatformError.custodyError {
            metadata = nil
        }

        let tag = applicationTag(for: keyHandle)
        var removedKey = false
        if let metadata, let keyType = KeyType(rawValue: metadata.keyType) {
            switch keyType {
            case .p256, .hpkeP256:
                removedKey = try await deleteConfirmed(
                    keyHandle, tag: tag, from: p256Store(for: metadata, handle: keyHandle)
                )
            case .ed25519:
                break
            }
        } else {
            let store = makeP256Store(mintBacking)
            if try await store.contains(tag: tag) {
                removedKey = try await deleteConfirmed(keyHandle, tag: tag, from: store)
            }
        }

        let deleteStatus = SecItemDelete(baseQuery(for: keyHandle) as CFDictionary)
        switch deleteStatus {
        case errSecSuccess:
            break
        case errSecItemNotFound:
            guard removedKey else { throw PlatformError.keyNotFound(keyHandle) }
        default:
            throw PlatformError.keychainError(deleteStatus)
        }

        // Confirm deletion by attempting a re-fetch.
        guard companionAbsent(handle: keyHandle) else {
            // An item is still present -- destruction cannot be confirmed.
            throw PlatformError.destructionFailed(keyHandle)
        }

        return DestructionAttestation(method: .softwareOnly, confirmed: true)
    }

    /// Deletes the key under `tag` from `store` and confirms it is gone.
    /// Returns whether a key was deleted.
    private nonisolated func deleteConfirmed(
        _ keyHandle: String, tag: Data, from store: any P256KeyStore
    ) async throws -> Bool {
        let deleted = try await store.delete(tag: tag)
        guard try await !store.contains(tag: tag) else {
            throw PlatformError.destructionFailed(keyHandle)
        }
        return deleted
    }

    // MARK: dhAgree

    /// Performs Diffie-Hellman key agreement with an HPKE P-256 key and
    /// returns the 32-byte shared secret.
    ///
    /// The key agrees in the store its record names
    /// (`.ecdhKeyExchangeStandard`), returning the x-coordinate of the
    /// agreed point. The peer must be a 65-byte uncompressed point on the
    /// curve; CryptoKit checks it before the store sees it.
    ///
    /// A signing key never agrees: an Ed25519 or P-256 key is refused before
    /// any key material is touched, because the custody interface has no
    /// cross-purpose agreement (ADR-021, 2026-10-18 amendment).
    ///
    /// - Parameters:
    ///   - keyHandle: The key id of an `"hpke-p256"` key.
    ///   - peerPublic: The peer's 65-byte uncompressed P-256 public key.
    /// - Returns: 32-byte shared secret.
    /// - Throws: ``PlatformError/keyNotFound(_:)`` if the handle is
    ///   unknown, ``PlatformError/wrongKeyType(_:)`` if it names a signing
    ///   key, ``PlatformError/biometricAuthenticationFailed(_:)`` if
    ///   biometric gating is active and authentication fails,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures,
    ///   ``PlatformError/custodyError(_:)`` if the peer public key is invalid
    ///   or the agreement fails.
    ///
    /// See ADR-025 Key custody and ADR-006 `dh_agree`.
    @concurrent
    func dhAgree(_ keyHandle: String, peerPublic: Data) async throws -> Data {
        let metadata = try fetchMetadata(for: keyHandle)
        let storedType = try Self.keyType(of: metadata, handle: keyHandle)
        switch storedType {
        case .hpkeP256:
            return try await agreeP256(keyHandle, metadata: metadata, peerPublic: peerPublic)
        case .ed25519, .p256:
            throw PlatformError.wrongKeyType(
                "dhAgree requires an HPKE P-256 key; '\(keyHandle)' is \(storedType.rawValue), and a signing key never agrees"
            )
        }
    }

    // MARK: derivePseudonym

    /// Derives the deterministic, context-scoped P-256 pseudonym of an
    /// Ed25519 identity key (spec §9.10.4.A) and returns its 33-byte
    /// compressed point.
    ///
    /// Reads the Ed25519 seed for `keyHandle` from Keychain (native software
    /// custody keys the recipe on this seed, §9.10.4 native interim), passes
    /// it to the shared Rust helper `p256SoftwarePseudonymPoint`, and wipes
    /// the local copy. The helper runs `pseudonym_secret = HKDF-SHA256(seed,
    /// "scp-pseudonym-secret-v1")`, `context_seed = HMAC-SHA256(
    /// pseudonym_secret, contextId || "scp-pseudonym")`, the FIPS 186-5
    /// A.2.1 reduction to a scalar, and returns the point. No pseudonym key
    /// is stored, and none can sign.
    ///
    /// **CRITICAL:** The HMAC key is derived from the private seed. Keying it
    /// on the public key would be a membership-enumeration oracle: anyone who
    /// knows a member's public key could compute their pseudonym for any
    /// context and check relay subscriptions.
    ///
    /// - Parameters:
    ///   - keyHandle: The handle of the **identity** Ed25519 key.
    ///   - contextId: The raw context ID bytes.
    /// - Returns: The 33-byte SEC1 compressed P-256 point.
    /// - Throws: ``PlatformError/wrongKeyType(_:)`` if `keyHandle` is not an
    ///   Ed25519 key, ``PlatformError/keyNotFound(_:)`` if the handle is
    ///   unknown (including after ``destroyKey(_:)``),
    ///   ``PlatformError/biometricAuthenticationFailed(_:)`` if biometric
    ///   gating is active and authentication fails,
    ///   ``PlatformError/keychainError(_:)`` for Keychain failures. The
    ///   shared Rust helper's error propagates unchanged:
    ///   ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7005` if the seed
    ///   is not 32 bytes. Any other error surfaces as
    ///   ``PlatformError/custodyError(_:)``.
    ///
    /// See spec §9.10.4.A and `derive_pseudonym` in
    /// `scp-crypto/src/pseudonym.rs` for the Rust reference.
    @concurrent
    func derivePseudonym(
        _ keyHandle: String,
        contextId: Data
    ) async throws -> Data {
        try derivePseudonymPoint(
            method: "derivePseudonym",
            identityHandle: keyHandle,
            contextId: contextId,
            epoch: nil
        )
    }

    // MARK: deriveRotatablePseudonym

    /// Derives the deterministic, context-scoped, epoch-rotatable P-256
    /// pseudonym of an Ed25519 identity key (rotation per spec §9.10.4.1,
    /// derivation per §9.10.4.A) and returns its 33-byte compressed point.
    ///
    /// Identical to ``derivePseudonym(_:contextId:)`` except that the
    /// context seed is `HMAC-SHA256(pseudonym_secret,
    /// contextId || BE64(pseudonymEpoch) || "scp-pseudonym-v2")`.
    ///
    /// - Parameters:
    ///   - keyHandle: The handle of the **identity** Ed25519 key.
    ///   - contextId: The raw context ID bytes.
    ///   - pseudonymEpoch: The rotation epoch.
    /// - Returns: The 33-byte SEC1 compressed P-256 point.
    /// - Throws: The same errors as ``derivePseudonym(_:contextId:)``.
    @concurrent
    func deriveRotatablePseudonym(
        _ keyHandle: String,
        contextId: Data,
        pseudonymEpoch: UInt64
    ) async throws -> Data {
        try derivePseudonymPoint(
            method: "deriveRotatablePseudonym",
            identityHandle: keyHandle,
            contextId: contextId,
            epoch: pseudonymEpoch
        )
    }

    // MARK: custodyType

    /// Returns the custody type of the key `keyHandle` names, in the
    /// vocabulary the bridge reads (`KeyCustodyProvider.custody_type`): the
    /// custody string recorded in the key's companion at mint, never one
    /// derived from the key type.
    ///
    /// - A P-256 or HPKE P-256 key the Secure Enclave holds is recorded as
    ///   `"hardware"`: ADR-025's `CustodyType.secureEnclave`, which the
    ///   bridge reads as hardware custody.
    /// - An Ed25519 key, or a P-256 key the platform signer holds
    ///   on a host without an enclave, is recorded as `"software"`, or
    ///   `"software_biometric"` when it was minted under
    ///   ``BiometricPolicy/required`` (ADR-025's `CustodyType.keychain`).
    /// - An id whose record the Keychain does not return, or whose recorded
    ///   custody is none of those strings, is `"in_memory"`, the weakest
    ///   custody the bridge knows, so no key is reported stronger than it is.
    ///
    /// The lookup reads attributes only and never prompts.
    ///
    /// See ADR-025 criterion 1, Biometric gating, and 17.8 of the SCP
    /// specification.
    ///
    /// - Parameter keyHandle: The key id.
    /// - Returns: `"hardware"`, `"software"`, `"software_biometric"` or
    ///   `"in_memory"`.
    nonisolated func custodyType(_ keyHandle: String) -> String {
        guard let recorded = try? fetchMetadata(for: keyHandle).custodyType else { return "in_memory" }
        switch recorded {
        case "hardware", "software", "software_biometric":
            return recorded
        default:
            return "in_memory"
        }
    }
}

// MARK: - UniFFI KeyCustodyProvider conformance

/// `AppleKeyCustody` as the bridge's `KeyCustodyProvider` (ADR-025): each
/// witness forwards to the Swift-idiomatic method above and converts every
/// failure into the one error type UniFFI accepts from a callback, `ScpError`.
///
/// Error mapping follows the host contract on `KeyCustodyProvider` in
/// `crates/scp-ffi/uniffi/src/lib.rs`:
/// - an `ScpError` from the shared Rust helpers passes through unchanged;
/// - ``PlatformError/keyNotFound(_:)`` becomes `SCP-CRYPTO-4006`, which the
///   bridge reports as key-not-found;
/// - ``PlatformError/mintRollbackIncomplete(keyId:cause:)`` becomes
///   `SCP-CRYPTO-4060` whose message names the key id to destroy;
/// - every other failure becomes `SCP-CRYPTO-4060`, the custody error,
///   carrying the adapter's description.
///
/// The adapter holds Ed25519 keys in the Keychain and P-256 and
/// HPKE P-256 keys in the Secure Enclave, or in the platform signer on a
/// host without one. An enclave host whose enclave cannot create a key
/// fails closed with `SCP-CRYPTO-4060`.
extension AppleKeyCustody: KeyCustodyProvider {
    /// Code the bridge reports as key-not-found.
    private nonisolated static let keyNotFoundCode = "SCP-CRYPTO-4006"
    /// Code the bridge reports as a custody failure.
    private nonisolated static let custodyErrorCode = "SCP-CRYPTO-4060"

    /// Converts any adapter failure into the `ScpError` the bridge accepts.
    private nonisolated static func providerError(_ error: Error) -> ScpError {
        switch error {
        case let scpError as ScpError:
            return scpError
        case let PlatformError.keyNotFound(handle):
            return .Crypto(msg: "Key not found for key id '\(handle)'", code: keyNotFoundCode)
        case let PlatformError.mintRollbackIncomplete(keyId, cause):
            return .Crypto(
                msg: "Key generation failed (\(cause)); key id '\(keyId)' remains and must be destroyed",
                code: custodyErrorCode
            )
        default:
            return .Crypto(msg: error.localizedDescription, code: custodyErrorCode)
        }
    }

    /// Runs `body` and rethrows its failure as an `ScpError`.
    private nonisolated static func bridged<T>(_ body: () async throws -> T) async throws -> T {
        do {
            return try await body()
        } catch {
            throw providerError(error)
        }
    }

    public func sign(keyId: String, message: Data) async throws -> Data {
        try await Self.bridged { try await sign(keyId, data: message) }
    }

    public func getPublicKey(keyId: String) async throws -> CustodyPublicKey {
        try await Self.bridged {
            let keyType: CustodyKeyType = switch try fetchKeyType(for: keyId) {
            case .ed25519: .ed25519
            case .p256: .p256
            case .hpkeP256: .hpkeP256
            }
            let role = try fetchRole(for: keyId).custodyKeyRole
            let publicKey = try await publicKey(keyId)
            return CustodyPublicKey(keyType: keyType, publicKey: publicKey, role: role)
        }
    }

    public func destroyKey(keyId: String) async throws {
        try await Self.bridged { _ = try await destroyKey(keyId) }
    }

    public func generateKeypair(keyType: CustodyKeyType, role: CustodyKeyRole) async throws -> String {
        try await Self.bridged {
            let adapterType: KeyType = switch keyType {
            case .ed25519: .ed25519
            case .p256: .p256
            case .hpkeP256: .hpkeP256
            }
            return try await mintKey(keyType: adapterType, role: role)
        }
    }

    public func dhAgree(keyId: String, peerPublic: Data) async throws -> Data {
        try await Self.bridged { try await dhAgree(keyId, peerPublic: peerPublic) }
    }

    public func derivePseudonym(keyId: String, contextId: Data) async throws -> Data {
        try await Self.bridged { try await derivePseudonym(keyId, contextId: contextId) }
    }

    public func deriveRotatablePseudonym(
        keyId: String,
        contextId: Data,
        pseudonymEpoch: UInt64
    ) async throws -> Data {
        try await Self.bridged {
            try await deriveRotatablePseudonym(keyId, contextId: contextId, pseudonymEpoch: pseudonymEpoch)
        }
    }

    public nonisolated func custodyType(keyId: String) -> String {
        custodyType(keyId)
    }
}
