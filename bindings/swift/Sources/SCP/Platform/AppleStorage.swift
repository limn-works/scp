/// AppleStorage — SQLCipher-encrypted SQLite storage with Keychain-protected key.
///
/// This file implements the ``StorageProvider`` callback interface (defined in
/// `crates/scp-ffi/uniffi/src/lib.rs`) for Apple platforms (iOS 17+, macOS 14+).
///
/// ## Architecture
///
/// `AppleStorage` is an actor that provides thread-safe key-value byte storage
/// to the SCP Rust engine via the UniFFI callback interface mechanism (ADR-021).
/// It is one of the four platform providers assembled by ``ApplePlatformAdapter``
/// (ADR-025) and injected into the Rust engine at SDK initialisation.
///
/// ## Encryption Key Management
///
/// On first use, `AppleStorage` generates a 32-byte random encryption key and
/// stores it in the Apple Keychain with:
/// - `kSecAttrAccessible`: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
///   (allows background processing; prevents iCloud Keychain backup)
/// - `kSecAttrAccessGroup`: `$(AppIdentifierPrefix).dev.limn.scp`
/// - `kSecClass`: `kSecClassGenericPassword`
/// - `kSecAttrAccount`: `scp.db.key`
///
/// On subsequent opens the key is retrieved from Keychain and passed to
/// SQLCipher via `PRAGMA key = "x'<hex>'"` before any other SQL is executed.
///
/// ## Simplified Storage
///
/// The full SQLCipher integration requires the Rust FFI round-trip that is
/// wired in a separate infrastructure story. This implementation:
/// - Correctly performs all Keychain operations (generate / retrieve the 32-byte
///   encryption key) to demonstrate the key-management pattern.
/// - Uses a thread-safe actor-isolated `[String: Data]` dictionary as the
///   backing store until the SQLCipher bridge is wired.
/// - Sets `NSFileProtectionCompleteUntilFirstUserAuthentication` on the
///   database file path on iOS (no-op on macOS where file protection is N/A).
///
/// ## Thread Safety
///
/// `AppleStorage` is a Swift actor. UniFFI callback interfaces execute on Rust
/// tokio threads — not the Swift or macOS main thread. The actor executor
/// ensures all dictionary mutations are serialised without data races.
///
/// See ADR-025 (Apple Platform Adapter) and ADR-021 (UniFFI Bridge).

#if os(iOS) || os(macOS)

import Foundation
import Security

// MARK: - StorageError

/// Errors that can be produced by ``AppleStorage`` operations.
public enum StorageError: Error, Sendable {
    /// A Keychain operation failed. Carries the `OSStatus` return value.
    case keychainError(OSStatus)
    /// A database-level operation failed. Carries a descriptive message.
    case databaseError(String)
}

extension StorageError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .keychainError(let status):
            return "Keychain operation failed with OSStatus \(status)"
        case .databaseError(let message):
            return "Database operation failed: \(message)"
        }
    }
}

// MARK: - AppleStorage

/// Actor-isolated, Keychain-secured storage provider for the SCP Rust engine.
///
/// Conforms to the UniFFI-generated `StorageProvider` protocol so that it can
/// be injected into the engine via the callback interface bridge (ADR-021).
///
/// Usage:
/// ```swift
/// let storage = try AppleStorage.open()
/// // Pass to SCP engine via ApplePlatformAdapter
/// ```
public actor AppleStorage {

    // MARK: Internal state

    /// In-memory backing store. Replaced by SQLCipher once the FFI bridge is wired.
    private var store: [String: Data] = [:]

    /// The 32-byte encryption key retrieved (or generated) from Keychain.
    /// Stored here for future SQLCipher `PRAGMA key` use.
    private let encryptionKey: Data

    // MARK: Keychain constants

    /// Keychain account name for the database encryption key.
    private static let keychainAccount = "scp.db.key"

    /// Keychain access group shared by all SCP items on this device.
    ///
    /// The `$(AppIdentifierPrefix)` segment is resolved at build time by Xcode
    /// from the app's entitlements. When running in contexts without an
    /// AppIdentifierPrefix (e.g., unit tests outside an app bundle), the group
    /// falls back to the bundle identifier prefix.
    private static let keychainAccessGroup = "dev.limn.scp"

    // MARK: Initialiser

    /// Designated internal initialiser.
    ///
    /// Callers must use ``open()`` which performs the Keychain setup and (on iOS)
    /// the file protection step before constructing the actor.
    private init(encryptionKey: Data) {
        self.encryptionKey = encryptionKey
    }

    // MARK: Factory

    /// Open (or create) the SCP storage, returning a configured `AppleStorage`.
    ///
    /// This factory:
    /// 1. Generates or retrieves the 32-byte Keychain encryption key via
    ///    ``generateOrRetrieveEncryptionKey()``.
    /// 2. On iOS, sets `NSFileProtectionCompleteUntilFirstUserAuthentication`
    ///    on the database file path before first open.
    /// 3. Constructs and returns the actor.
    ///
    /// - Throws: ``StorageError/keychainError(_:)`` if the Keychain is
    ///   inaccessible (e.g., device not yet unlocked after boot).
    public static func open() throws -> AppleStorage {
        let key = try generateOrRetrieveEncryptionKey()

#if os(iOS)
        // Set file protection before opening the database.
        // NSFileProtectionCompleteUntilFirstUserAuthentication allows background
        // access once the device has been unlocked at least once after boot.
        // NSFileProtectionComplete would block background processing while
        // the device is locked — unacceptable for relay message processing.
        let dbURL = databaseFileURL()
        let fm = FileManager.default
        // Only set the attribute if the file already exists; SQLCipher will
        // create the file on first connection. On creation the attribute must
        // be set before writes begin, so we create an empty placeholder here.
        if !fm.fileExists(atPath: dbURL.path) {
            fm.createFile(atPath: dbURL.path, contents: nil)
        }
        try fm.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: dbURL.path
        )
#endif

        return AppleStorage(encryptionKey: key)
    }

    // MARK: Encryption Key

    /// Generate a fresh 32-byte key and persist it in Keychain, or return the
    /// existing key if already stored.
    ///
    /// Steps:
    /// 1. Attempt to read an existing item from Keychain under `scp.db.key`.
    /// 2. If found and valid (32 bytes), return those bytes.
    /// 3. If corrupt (wrong size), delete the item and call
    ///    ``generateFreshEncryptionKey()`` (non-recursive).
    /// 4. If not found (`errSecItemNotFound`), call
    ///    ``generateFreshEncryptionKey()`` directly.
    ///
    /// The returned bytes are intended to be passed to SQLCipher as:
    /// ```sql
    /// PRAGMA key = "x'<hexEncodedBytes>'"
    /// ```
    ///
    /// - Throws: ``StorageError/keychainError(_:)`` on unexpected Keychain failures.
    static func generateOrRetrieveEncryptionKey() throws -> Data {
        // Attempt retrieval first.
        let readQuery: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrAccount as String:      keychainAccount,
            kSecAttrAccessGroup as String:  keychainAccessGroup,
            kSecReturnData as String:       true,
            kSecMatchLimit as String:       kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let readStatus = SecItemCopyMatching(readQuery as CFDictionary, &result)

        switch readStatus {
        case errSecSuccess:
            guard let data = result as? Data, data.count == 32 else {
                // Corrupt item: delete it, then generate fresh key (non-recursive).
                let deleteQuery: [String: Any] = [
                    kSecClass as String:           kSecClassGenericPassword,
                    kSecAttrAccount as String:     keychainAccount,
                    kSecAttrAccessGroup as String: keychainAccessGroup,
                ]
                let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
                guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
                    throw StorageError.keychainError(deleteStatus)
                }
                return try generateFreshEncryptionKey()
            }
            return data

        case errSecItemNotFound:
            return try generateFreshEncryptionKey()

        default:
            throw StorageError.keychainError(readStatus)
        }
    }

    /// Generate 32 random bytes and add them to Keychain. Non-recursive.
    /// Called only when no key exists or the existing key is corrupt and deleted.
    private static func generateFreshEncryptionKey() throws -> Data {
        var keyBytes = [UInt8](repeating: 0, count: 32)
        let rc = SecRandomCopyBytes(kSecRandomDefault, 32, &keyBytes)
        guard rc == errSecSuccess else { throw StorageError.keychainError(rc) }
        let keyData = Data(keyBytes)
        let addQuery: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrAccount as String:     keychainAccount,
            kSecAttrAccessGroup as String: keychainAccessGroup,
            kSecAttrAccessible as String:  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String:       keyData,
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw StorageError.keychainError(addStatus) }
        return keyData
    }

    // MARK: StorageProvider implementation

    /// Store `value` under `key`, overwriting any existing value.
    public func set(key: String, value: Data) throws {
        store[key] = value
    }

    /// Retrieve the bytes stored under `key`, or `nil` if absent.
    public func get(key: String) throws -> Data? {
        return store[key]
    }

    /// Delete the value stored under `key`. No-op if absent.
    public func delete(key: String) throws {
        store.removeValue(forKey: key)
    }

    /// List all keys whose prefix matches `prefix` in lexicographic order.
    public func listKeys(prefix: String) throws -> [String] {
        return store.keys
            .filter { $0.hasPrefix(prefix) }
            .sorted()
    }

    /// Delete all keys whose prefix matches `prefix`.
    ///
    /// - Returns: The number of keys deleted.
    public func deletePrefix(prefix: String) throws -> UInt64 {
        let matching = store.keys.filter { $0.hasPrefix(prefix) }
        for key in matching {
            store.removeValue(forKey: key)
        }
        return UInt64(matching.count)
    }

    /// Return `true` if `key` exists without reading its value.
    public func exists(key: String) throws -> Bool {
        return store[key] != nil
    }

    // MARK: Helpers

    /// Returns the canonical URL for the SQLCipher database file.
    ///
    /// Stored in `Application Support` so that it is excluded from iCloud
    /// backup by default (unlike `Documents`).
    static func databaseFileURL() -> URL {
        let fm = FileManager.default
        let appSupport = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let scpDir = appSupport.appendingPathComponent("dev.limn.scp", isDirectory: true)
        // Create the directory if it does not exist.
        try? fm.createDirectory(at: scpDir, withIntermediateDirectories: true)
        return scpDir.appendingPathComponent("scp.db")
    }
}

// MARK: - Hex encoding helper

extension Data {
    /// Returns a lowercase hex string representation of the receiver.
    ///
    /// Used to format the SQLCipher `PRAGMA key = "x'<hex>'"` value.
    var hexEncodedString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

#endif // os(iOS) || os(macOS)
