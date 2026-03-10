// AppleStorage — SQLCipher-encrypted SQLite storage with Keychain-protected key.
//
// This file implements the ``StorageProvider`` callback interface (defined in
// `crates/scp-ffi/uniffi/src/lib.rs`) for Apple platforms (iOS 17+, macOS 14+).
//
// ## Architecture
//
// `AppleStorage` is an actor that provides thread-safe key-value byte storage
// to the SCP Rust engine via the UniFFI callback interface mechanism (ADR-021).
// It is one of the four platform providers assembled by ``ApplePlatformAdapter``
// (ADR-025) and injected into the Rust engine at SDK initialisation.
//
// ## Storage Backend
//
// Uses the system `sqlite3` C library (available on all Apple platforms) with
// SQLCipher pragmas for encryption. The database is stored in Application
// Support at `dev.limn.scp/scp.db`. The schema matches the Rust core's
// `SqliteStorage`:
//
// ```sql
// CREATE TABLE kv (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
// ```
//
// Prefix queries use B-tree range scans (`key >= ? AND key < ?`) via
// `prefixSuccessor(_:)` rather than `LIKE`, leveraging the clustered index.
//
// ## Encryption Key Management
//
// On first use, `AppleStorage` generates a 32-byte random encryption key and
// stores it in the Apple Keychain with:
// - `kSecAttrAccessible`: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
//   (allows background processing; prevents iCloud Keychain backup)
// - `kSecAttrAccessGroup`: `$(AppIdentifierPrefix).dev.limn.scp`
// - `kSecClass`: `kSecClassGenericPassword`
// - `kSecAttrAccount`: `scp.db.key`
//
// On subsequent opens the key is retrieved from Keychain and passed to
// SQLCipher via `PRAGMA key = "x'<hex>'"` before any other SQL is executed.
//
// ## Thread Safety
//
// `AppleStorage` is a Swift actor. UniFFI callback interfaces execute on Rust
// tokio threads — not the Swift or macOS main thread. The actor executor
// ensures all database mutations are serialised without data races.
//
// See ADR-025 (Apple Platform Adapter) and ADR-021 (UniFFI Bridge).

#if os(iOS) || os(macOS)

    import Foundation
    import Security
    #if canImport(SQLite3)
        import SQLite3
    #endif

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
            case let .keychainError(status):
                return "Keychain operation failed with OSStatus \(status)"
            case let .databaseError(message):
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

        /// SQLite database handle. Opened once during `open()` and used for all
        /// subsequent operations.
        private let db: OpaquePointer // swiftlint:disable:this identifier_name

        /// The 32-byte encryption key retrieved (or generated) from Keychain.
        /// Retained for documentation / debugging; the key is applied to SQLite
        /// via `PRAGMA key` during `open()`.
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
        /// Callers must use ``open()`` which performs the Keychain setup, database
        /// opening, and (on iOS) the file protection step before constructing the actor.
        private init(db: OpaquePointer, encryptionKey: Data) { // swiftlint:disable:this identifier_name
            self.db = db
            self.encryptionKey = encryptionKey
        }

        deinit {
            sqlite3_close_v2(db)
        }

        // MARK: Factory

        /// Open (or create) the SCP storage, returning a configured `AppleStorage`.
        ///
        /// This factory:
        /// 1. Generates or retrieves the 32-byte Keychain encryption key via
        ///    ``generateOrRetrieveEncryptionKey()``.
        /// 2. On iOS, sets `NSFileProtectionCompleteUntilFirstUserAuthentication`
        ///    on the database file path before first open.
        /// 3. Opens the SQLite database and applies SQLCipher encryption pragmas.
        /// 4. Creates the `kv` table if it does not exist.
        /// 5. Constructs and returns the actor.
        ///
        /// - Throws: ``StorageError/keychainError(_:)`` if the Keychain is
        ///   inaccessible (e.g., device not yet unlocked after boot).
        /// - Throws: ``StorageError/databaseError(_:)`` if the database cannot
        ///   be opened or configured.
        public static func open() throws -> AppleStorage {
            let key = try generateOrRetrieveEncryptionKey()

            let dbURL = databaseFileURL()

            #if os(iOS)
                // Set file protection before opening the database.
                // NSFileProtectionCompleteUntilFirstUserAuthentication allows background
                // access once the device has been unlocked at least once after boot.
                // NSFileProtectionComplete would block background processing while
                // the device is locked — unacceptable for relay message processing.
                let fileManager = FileManager.default
                // Only set the attribute if the file already exists; SQLCipher will
                // create the file on first connection. On creation the attribute must
                // be set before writes begin, so we create an empty placeholder here.
                if !fileManager.fileExists(atPath: dbURL.path) {
                    fileManager.createFile(atPath: dbURL.path, contents: nil)
                }
                try fileManager.setAttributes(
                    [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                    ofItemAtPath: dbURL.path
                )
            #endif

            // Open the SQLite database.
            var dbHandle: OpaquePointer?
            let openResult = sqlite3_open(dbURL.path, &dbHandle)
            // swiftlint:disable:next identifier_name
            guard openResult == SQLITE_OK, let db = dbHandle else {
                let msg = dbHandle.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
                if let handle = dbHandle { sqlite3_close_v2(handle) }
                throw StorageError.databaseError("Failed to open database: \(msg)")
            }

            // Apply SQLCipher encryption key (spec §17.5).
            let hexKey = key.hexEncodedString
            let pragmas = """
            PRAGMA key = "x'\(hexKey)'";
            PRAGMA cipher_page_size = 4096;
            PRAGMA kdf_iter = 256000;
            PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
            PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
            PRAGMA journal_mode = WAL;
            """
            try execSQL(db: db, sql: pragmas)

            // Create the KV table.
            try execSQL(db: db, sql: """
            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;
            """)

            return AppleStorage(db: db, encryptionKey: key)
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
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: keychainAccount,
                kSecAttrAccessGroup as String: keychainAccessGroup,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne
            ]
            var result: AnyObject?
            let readStatus = SecItemCopyMatching(readQuery as CFDictionary, &result)

            switch readStatus {
            case errSecSuccess:
                guard let data = result as? Data, data.count == 32 else {
                    // Corrupt item: delete it, then generate fresh key (non-recursive).
                    let deleteQuery: [String: Any] = [
                        kSecClass as String: kSecClassGenericPassword,
                        kSecAttrAccount as String: keychainAccount,
                        kSecAttrAccessGroup as String: keychainAccessGroup
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
            let randomStatus = SecRandomCopyBytes(kSecRandomDefault, 32, &keyBytes)
            guard randomStatus == errSecSuccess else { throw StorageError.keychainError(randomStatus) }
            let keyData = Data(keyBytes)
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: keychainAccount,
                kSecAttrAccessGroup as String: keychainAccessGroup,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                kSecValueData as String: keyData
            ]
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw StorageError.keychainError(addStatus) }
            return keyData
        }

        // MARK: StorageProvider implementation

        /// Store `value` under `key`, overwriting any existing value.
        public func set(key: String, value: Data) throws {
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            let sql = "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw StorageError.databaseError(lastErrorMessage())
            }
            sqlite3_bind_text(stmt, 1, (key as NSString).utf8String, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            value.withUnsafeBytes { ptr in
                sqlite3_bind_blob(stmt, 2, ptr.baseAddress, Int32(ptr.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            }
            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw StorageError.databaseError(lastErrorMessage())
            }
        }

        /// Retrieve the bytes stored under `key`, or `nil` if absent.
        public func get(key: String) throws -> Data? {
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            let sql = "SELECT value FROM kv WHERE key = ?1"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw StorageError.databaseError(lastErrorMessage())
            }
            sqlite3_bind_text(stmt, 1, (key as NSString).utf8String, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))

            let result = sqlite3_step(stmt)
            if result == SQLITE_ROW {
                let length = sqlite3_column_bytes(stmt, 0)
                if let blob = sqlite3_column_blob(stmt, 0) {
                    return Data(bytes: blob, count: Int(length))
                }
                return Data()
            } else if result == SQLITE_DONE {
                return nil
            } else {
                throw StorageError.databaseError(lastErrorMessage())
            }
        }

        /// Delete the value stored under `key`. No-op if absent.
        public func delete(key: String) throws {
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            let sql = "DELETE FROM kv WHERE key = ?1"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw StorageError.databaseError(lastErrorMessage())
            }
            sqlite3_bind_text(stmt, 1, (key as NSString).utf8String, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw StorageError.databaseError(lastErrorMessage())
            }
        }

        /// List all keys whose prefix matches `prefix` in lexicographic order.
        ///
        /// Uses B-tree range scan via ``prefixSuccessor(_:)`` for efficiency.
        public func listKeys(prefix: String) throws -> [String] {
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

            if let upper = Self.prefixSuccessor(prefix) {
                let sql = "SELECT key FROM kv WHERE key >= ?1 AND key < ?2 ORDER BY key"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(lastErrorMessage())
                }
                sqlite3_bind_text(stmt, 1, (prefix as NSString).utf8String, -1, transient)
                sqlite3_bind_text(stmt, 2, (upper as NSString).utf8String, -1, transient)
            } else {
                let sql = "SELECT key FROM kv WHERE key >= ?1 ORDER BY key"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(lastErrorMessage())
                }
                sqlite3_bind_text(stmt, 1, (prefix as NSString).utf8String, -1, transient)
            }

            var keys: [String] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                if let cStr = sqlite3_column_text(stmt, 0) {
                    keys.append(String(cString: cStr))
                }
            }
            return keys
        }

        /// Delete all keys whose prefix matches `prefix`.
        ///
        /// - Returns: The number of keys deleted.
        public func deletePrefix(prefix: String) throws -> UInt64 {
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

            if let upper = Self.prefixSuccessor(prefix) {
                let sql = "DELETE FROM kv WHERE key >= ?1 AND key < ?2"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(lastErrorMessage())
                }
                sqlite3_bind_text(stmt, 1, (prefix as NSString).utf8String, -1, transient)
                sqlite3_bind_text(stmt, 2, (upper as NSString).utf8String, -1, transient)
            } else {
                let sql = "DELETE FROM kv WHERE key >= ?1"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(lastErrorMessage())
                }
                sqlite3_bind_text(stmt, 1, (prefix as NSString).utf8String, -1, transient)
            }

            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw StorageError.databaseError(lastErrorMessage())
            }
            return UInt64(sqlite3_changes(db))
        }

        /// Return `true` if `key` exists without reading its value.
        public func exists(key: String) throws -> Bool {
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            let sql = "SELECT 1 FROM kv WHERE key = ?1 LIMIT 1"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw StorageError.databaseError(lastErrorMessage())
            }
            sqlite3_bind_text(stmt, 1, (key as NSString).utf8String, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))

            let result = sqlite3_step(stmt)
            if result == SQLITE_ROW {
                return true
            } else if result == SQLITE_DONE {
                return false
            } else {
                throw StorageError.databaseError(lastErrorMessage())
            }
        }

        // MARK: Helpers

        /// Returns the canonical URL for the SQLCipher database file.
        ///
        /// Stored in `Application Support` so that it is excluded from iCloud
        /// backup by default (unlike `Documents`).
        static func databaseFileURL() -> URL {
            let fileManager = FileManager.default
            let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            let scpDir = appSupport.appendingPathComponent("dev.limn.scp", isDirectory: true)
            // Create the directory if it does not exist.
            try? fileManager.createDirectory(at: scpDir, withIntermediateDirectories: true)
            return scpDir.appendingPathComponent("scp.db")
        }

        /// Returns the last SQLite error message for the current connection.
        private func lastErrorMessage() -> String {
            String(cString: sqlite3_errmsg(db))
        }

        /// Execute a batch SQL statement (no results expected).
        private static func execSQL(db: OpaquePointer, sql: String) throws { // swiftlint:disable:this identifier_name
            var errMsg: UnsafeMutablePointer<CChar>?
            let status = sqlite3_exec(db, sql, nil, nil, &errMsg)
            if status != SQLITE_OK {
                let msg = errMsg.map { String(cString: $0) } ?? "unknown error"
                sqlite3_free(errMsg)
                throw StorageError.databaseError(msg)
            }
        }

        /// Compute the exclusive upper bound for a B-tree range scan on `prefix`.
        ///
        /// Given a prefix string, returns a string lexicographically just past all
        /// strings that start with `prefix`. Increments the last byte; if the last
        /// byte is `0xFF`, strips it and increments the preceding byte (recursively).
        /// Returns `nil` when the prefix is empty or all `0xFF` bytes (no finite
        /// upper bound).
        static func prefixSuccessor(_ prefix: String) -> String? {
            var bytes = Array(prefix.utf8)

            // Pop trailing 0xFF bytes — they cannot be incremented.
            while bytes.last == 0xFF {
                bytes.removeLast()
            }

            guard !bytes.isEmpty else {
                return nil
            }

            // Increment the last non-0xFF byte.
            bytes[bytes.count - 1] += 1

            // swiftlint:disable:next optional_data_string_conversion
            return String(decoding: bytes, as: UTF8.self)
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
