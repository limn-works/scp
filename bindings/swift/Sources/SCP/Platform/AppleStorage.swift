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
            try open(at: databaseFileURL(), encryptionKey: generateOrRetrieveEncryptionKey())
        }

        /// Open (or create) an SCP storage database at `fileURL`, encrypted
        /// under `encryptionKey`.
        ///
        /// ``open()`` calls this with the canonical database path and the
        /// Keychain-held key, and it is the call an app makes. A caller that
        /// holds its own key and its own path calls this one: the storage tests
        /// under `bindings/swift/Tests/SCPTests/Platform/` do, so that they
        /// exercise these methods against a database this process created rather
        /// than against this device's Keychain item and this device's storage.
        ///
        /// - Parameters:
        ///   - fileURL: Where this connection reads and writes its database
        ///     file. On iOS this method sets file protection on that path before
        ///     it opens the connection.
        ///   - encryptionKey: 32 bytes SQLCipher takes through `PRAGMA key`.
        /// - Throws: ``StorageError/databaseError(_:)`` if the database cannot
        ///   be opened or configured.
        static func open(at fileURL: URL, encryptionKey: Data) throws -> AppleStorage {
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
                if !fileManager.fileExists(atPath: fileURL.path) {
                    fileManager.createFile(atPath: fileURL.path, contents: nil)
                }
                try fileManager.setAttributes(
                    [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                    ofItemAtPath: fileURL.path
                )
            #endif

            // Open the SQLite database.
            var dbHandle: OpaquePointer?
            let openResult = sqlite3_open(fileURL.path, &dbHandle)
            // swiftlint:disable:next identifier_name
            guard openResult == SQLITE_OK, let db = dbHandle else {
                let msg = dbHandle.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
                if let handle = dbHandle {
                    sqlite3_close_v2(handle)
                }
                throw StorageError.databaseError("Failed to open database: \(msg)")
            }

            // Apply SQLCipher encryption key (spec §17.5).
            let hexKey = encryptionKey.hexEncodedString
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

            return AppleStorage(db: db, encryptionKey: encryptionKey)
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

        // MARK: Parameter binding

        /// Bind `value` to parameter `index` of `statement`, and throw when
        /// SQLite rejects that bind.
        ///
        /// **Why every call site reads this return code.** SQLite reports a
        /// rejected bind through a return code and leaves that parameter reading
        /// `NULL`, and a statement carrying `NULL` where a key belongs still
        /// steps to `SQLITE_DONE`. `DELETE FROM kv WHERE key = NULL` then
        /// matches no row and reports success, `SELECT 1 FROM kv WHERE key =
        /// NULL` reports absence for a key this database holds, and an insert
        /// writes a row holding no key. Reading this code is what turns each of
        /// those answers into a thrown error.
        ///
        /// **Why this method passes a byte count rather than a C string.**
        /// `sqlite3_bind_text` reads a negative length as "the bytes up to the
        /// first zero byte", so binding a key through a C string pointer stores
        /// `set(key: "a\u{0}b", …)` under the one-byte key `a`, and
        /// `set(key: "a\u{0}c", …)` then overwrites that same row. SQLite
        /// answers `SQLITE_OK` for that bind, so the return code this method
        /// reads rejects nothing there. Passing `value.utf8.count` is what
        /// gives two keys that differ after a zero byte two rows. That count
        /// also forbids the null pointer `NSString.utf8String` may answer, which
        /// SQLite reads as a request to bind `NULL` while still answering
        /// `SQLITE_OK`.
        ///
        /// - Parameters:
        ///   - value: Text SQLite copies before this call returns, because the
        ///     destructor argument is `SQLITE_TRANSIENT`.
        ///   - statement: A statement `sqlite3_prepare_v2` produced.
        ///   - index: A one-based parameter position.
        /// - Throws: `StorageError.databaseError` when `statement` is `nil`,
        ///   when `value` holds more UTF-8 bytes than an `Int32` counts, and
        ///   when `sqlite3_bind_text` answers anything other than `SQLITE_OK`.
        static func bindText(_ value: String, to statement: OpaquePointer?, at index: Int32) throws {
            guard let statement else {
                throw StorageError.databaseError("bindText received no prepared statement")
            }
            let utf8 = Array(value.utf8)
            guard let byteCount = Int32(exactly: utf8.count) else {
                throw StorageError.databaseError(
                    "bindText received \(utf8.count) UTF-8 bytes, which no Int32 length counts"
                )
            }
            let status = utf8.withUnsafeBufferPointer { buffer -> Int32 in
                guard let base = buffer.baseAddress else {
                    // `UnsafeBufferPointer.baseAddress` documents `nil` for an
                    // empty buffer, and SQLite reads a null pointer as a request
                    // to bind `NULL` while still answering `SQLITE_OK`, so this
                    // arm binds zero bytes of a literal instead. The Swift 6.2
                    // toolchain answers a non-null address for an empty
                    // `Array<UInt8>`, so no `swift test` case reaches this arm
                    // and none of them pins it.
                    return sqlite3_bind_text(statement, index, "", 0, transientDestructor)
                }
                return UnsafeRawPointer(base).withMemoryRebound(
                    to: CChar.self,
                    capacity: buffer.count
                ) { characters in
                    sqlite3_bind_text(statement, index, characters, byteCount, transientDestructor)
                }
            }
            guard status == SQLITE_OK else {
                throw StorageError.databaseError(errorMessage(for: statement))
            }
        }

        /// Bind `value` to parameter `index` of `statement` as a blob, and throw
        /// when SQLite rejects that bind.
        ///
        /// `bindText(_:to:at:)` states why every call site reads this return
        /// code. An empty `Data` may hand `withUnsafeBytes` a `nil` base
        /// address, and `sqlite3_bind_blob` reads a `nil` pointer as a request
        /// to bind `NULL`, so this method binds a zero-length blob for that
        /// case; the `kv` table declares `value BLOB NOT NULL`, and `NULL` would
        /// make an insert of empty bytes fail.
        ///
        /// - Throws: `StorageError.databaseError` when `statement` is `nil`, and
        ///   when SQLite answers anything other than `SQLITE_OK`.
        static func bindBlob(_ value: Data, to statement: OpaquePointer?, at index: Int32) throws {
            guard let statement else {
                throw StorageError.databaseError("bindBlob received no prepared statement")
            }
            let status = value.withUnsafeBytes { raw -> Int32 in
                guard let base = raw.baseAddress, raw.count > 0 else {
                    return sqlite3_bind_zeroblob(statement, index, 0)
                }
                return sqlite3_bind_blob(statement, index, base, Int32(raw.count), transientDestructor)
            }
            guard status == SQLITE_OK else {
                throw StorageError.databaseError(errorMessage(for: statement))
            }
        }

        /// `SQLITE_TRANSIENT`, which tells SQLite to copy a bound value's bytes
        /// before the binding call returns.
        ///
        /// The SQLite C header spells this constant as a cast of `-1` to a
        /// destructor pointer, and no Swift overlay exposes it, so this property
        /// rebuilds that cast.
        private static let transientDestructor = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

        /// The last error message SQLite recorded on the connection that
        /// prepared `statement`.
        private static func errorMessage(for statement: OpaquePointer) -> String {
            guard let handle = sqlite3_db_handle(statement) else {
                return "SQLite reported no connection for this statement"
            }
            return String(cString: sqlite3_errmsg(handle))
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
            try Self.bindText(key, to: stmt, at: 1)
            try Self.bindBlob(value, to: stmt, at: 2)
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
            try Self.bindText(key, to: stmt, at: 1)

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
            try Self.bindText(key, to: stmt, at: 1)
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

            if let upper = Self.prefixSuccessor(prefix) {
                let sql = "SELECT key FROM kv WHERE key >= ?1 AND key < ?2 ORDER BY key"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(lastErrorMessage())
                }
                try Self.bindText(prefix, to: stmt, at: 1)
                try Self.bindText(upper, to: stmt, at: 2)
            } else {
                let sql = "SELECT key FROM kv WHERE key >= ?1 ORDER BY key"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(lastErrorMessage())
                }
                try Self.bindText(prefix, to: stmt, at: 1)
            }

            var keys: [String] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                // `String(cString:)` stops at the first zero byte, which would
                // return `a` for a stored key `a\u{0}b` and would return one
                // string for two keys that differ only after that byte.
                // `sqlite3_column_bytes` reports how many bytes SQLite holds for
                // this column, and SQLite's documentation requires the call
                // order below: read the column through `sqlite3_column_text`
                // first, then ask for its byte count.
                guard let text = sqlite3_column_text(stmt, 0) else { continue }
                let byteCount = Int(sqlite3_column_bytes(stmt, 0))
                let bytes = Data(UnsafeBufferPointer(start: text, count: byteCount))
                // §17.3 of the persistence-and-storage spec states that keys are
                // UTF-8 strings, so bytes that decode as no UTF-8 string name a
                // key this storage never wrote. Throwing reports that, where
                // substituting U+FFFD would return a string naming no row.
                guard let key = String(bytes: bytes, encoding: .utf8) else {
                    throw StorageError.databaseError(
                        "a stored key of \(byteCount) bytes decodes as no UTF-8 string"
                    )
                }
                keys.append(key)
            }
            return keys
        }

        /// Delete all keys whose prefix matches `prefix`.
        ///
        /// - Returns: The number of keys deleted.
        public func deletePrefix(prefix: String) throws -> UInt64 {
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            if let upper = Self.prefixSuccessor(prefix) {
                let sql = "DELETE FROM kv WHERE key >= ?1 AND key < ?2"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(lastErrorMessage())
                }
                try Self.bindText(prefix, to: stmt, at: 1)
                try Self.bindText(upper, to: stmt, at: 2)
            } else {
                let sql = "DELETE FROM kv WHERE key >= ?1"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(lastErrorMessage())
                }
                try Self.bindText(prefix, to: stmt, at: 1)
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
            try Self.bindText(key, to: stmt, at: 1)

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
