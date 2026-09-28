// AppleStorage — SQLCipher-encrypted SQLite storage with Keychain-protected key.
//
// This file holds the SQLCipher storage adapter for Apple platforms (iOS 17+,
// macOS 14+). ADR-025, the Apple platform adapter, requires this adapter to conform
// to the UniFFI `StorageProvider` callback interface in
// `crates/scp-ffi/uniffi/src/lib.rs`. The shipped actor does not conform yet.
//
// ## Architecture
//
// `AppleStorage` is an actor that provides thread-safe key-value byte storage.
// ADR-025 has an `ApplePlatformAdapter` assemble the four platform providers and
// inject them into the Rust engine through the UniFFI callback interfaces (ADR-021).
// No `ApplePlatformAdapter` exists yet, so no code injects this actor into the Rust
// engine.
//
// ## Storage Backend
//
// The `sqlite3_` symbols this file calls through `import SQLite3` must resolve
// to the SQLCipher copy that `ScpFFI.xcframework` bundles, which receives the
// encryption key through `PRAGMA key`. `open(at:encryptionKey:cipherVersion:)` asks the
// connection for `PRAGMA cipher_version` and throws when the answer is empty,
// so a process whose symbols resolved to Apple's system SQLite, which ignores
// `PRAGMA key` and would write every value in the clear, opens no storage.
// The database is stored in Application
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
    /// ADR-025 requires this actor to conform to the UniFFI-generated
    /// `StorageProvider` protocol (ADR-021), and this actor does not conform
    /// yet: its methods throw `StorageError`, while that protocol declares
    /// `ScpError` as its error type, and UniFFI panics on the Rust side when a
    /// callback throws a type the callback does not declare.
    ///
    /// Usage:
    /// ```swift
    /// let storage = try AppleStorage.open()
    /// try await storage.set(key: "k", value: Data([1]))
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
        ///   - cipherVersion: Reads the SQLCipher version from the connection
        ///     after the key pragmas run, and throws when the connection is not
        ///     SQLCipher. Every production caller takes the default,
        ///     ``sqlCipherVersion(db:)``; a test passes a probe that answers the
        ///     way plain SQLite does, to prove this method runs the check.
        /// - Throws: ``StorageError/databaseError(_:)`` if the database cannot
        ///   be opened or configured, or if `cipherVersion` throws.
        static func open(
            at fileURL: URL,
            encryptionKey: Data,
            cipherVersion: (OpaquePointer) throws -> String = AppleStorage.sqlCipherVersion(db:)
        ) throws -> AppleStorage {
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
            // No `AppleStorage` owns `db` until the return below, so its
            // `deinit` cannot close the connection: every statement that can
            // throw between `sqlite3_open` and that return sits inside this
            // `do`, whose `catch` closes it.
            do {
                try execSQL(db: db, sql: pragmas)
                _ = try cipherVersion(db)

                // Create the KV table.
                try execSQL(db: db, sql: """
                CREATE TABLE IF NOT EXISTS kv (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                ) WITHOUT ROWID;
                """)
            } catch {
                sqlite3_close_v2(db)
                throw error
            }

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
            // `utf8CString` holds every UTF-8 byte of `value`, zero bytes
            // included, followed by one terminating zero, so its buffer is never
            // empty and its base address is never `nil`; the byte count leaves
            // that terminator out.
            let characters = value.utf8CString
            let byteCount = try sqliteByteCount(characters.count - 1, binder: "bindText")
            let status = characters.withUnsafeBufferPointer { buffer in
                sqlite3_bind_text(statement, index, buffer.baseAddress, byteCount, transientDestructor)
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
        /// - Throws: `StorageError.databaseError` when `statement` is `nil`,
        ///   when `value` holds more bytes than an `Int32` counts, and when
        ///   SQLite answers anything other than `SQLITE_OK`.
        static func bindBlob(_ value: Data, to statement: OpaquePointer?, at index: Int32) throws {
            guard let statement else {
                throw StorageError.databaseError("bindBlob received no prepared statement")
            }
            let byteCount = try sqliteByteCount(value.count, binder: "bindBlob")
            let status = value.withUnsafeBytes { raw -> Int32 in
                guard let base = raw.baseAddress, raw.count > 0 else {
                    return sqlite3_bind_zeroblob(statement, index, 0)
                }
                return sqlite3_bind_blob(statement, index, base, byteCount, transientDestructor)
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

        /// Ask SQLite to cap every string and blob on this connection at
        /// `bytes`, and return the cap SQLite applied.
        ///
        /// SQLite lowers a request above its compiled maximum to that maximum,
        /// and some releases raise a request below a compiled minimum to that
        /// minimum, so a caller reads the returned cap instead of assuming its
        /// request.
        /// Once the cap is in force, `sqlite3_bind_text` and
        /// `sqlite3_bind_blob` answer `SQLITE_TOOBIG` for a value longer than
        /// the cap. `AppleStorageTests` calls this method to make SQLite reject
        /// a bind inside each of the six key-value methods.
        ///
        /// - Parameter bytes: The `SQLITE_LIMIT_LENGTH` value to request. SQLite
        ///   leaves the cap unchanged for a negative value, so
        ///   `setLengthLimit(-1)` reads the cap in force.
        /// - Returns: The `SQLITE_LIMIT_LENGTH` value SQLite holds after the
        ///   request.
        func setLengthLimit(_ bytes: Int32) -> Int32 {
            _ = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, bytes)
            return sqlite3_limit(db, SQLITE_LIMIT_LENGTH, -1)
        }

        // MARK: Key-value operations

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

            return try Self.readKeys(from: stmt)
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

        /// Read `PRAGMA cipher_version` on `db` and return the SQLCipher
        /// version it reports.
        ///
        /// Plain SQLite ignores an unknown pragma without an error, so a
        /// process whose `sqlite3_` symbols resolved to the system library
        /// accepts `PRAGMA key` and then writes every value in the clear.
        /// SQLCipher answers `PRAGMA cipher_version` with one row, and plain
        /// SQLite answers it with no row, so `open(at:encryptionKey:cipherVersion:)` calls
        /// this method through its default `cipherVersion` argument and fails
        /// closed on that answer.
        ///
        /// - Throws: `StorageError.databaseError` when the statement cannot be
        ///   prepared or stepped, and when ``requireSQLCipherVersion(_:)``
        ///   rejects the rows it returned.
        static func sqlCipherVersion(db: OpaquePointer) throws -> String { // swiftlint:disable:this identifier_name
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_prepare_v2(db, "PRAGMA cipher_version;", -1, &stmt, nil) == SQLITE_OK else {
                throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
            }
            return try requireSQLCipherVersion(readKeys(from: stmt))
        }

        /// Return the one non-empty version `PRAGMA cipher_version` answered.
        ///
        /// - Throws: `StorageError.databaseError` when `rows` is not exactly
        ///   one non-empty string, which means SQLCipher is not the SQLite
        ///   library this process linked, so no value would be encrypted.
        static func requireSQLCipherVersion(_ rows: [String]) throws -> String {
            guard rows.count == 1, let version = rows.first, !version.isEmpty else {
                throw StorageError.databaseError(
                    "PRAGMA cipher_version returned \(rows.count) rows and no SQLCipher version, "
                        + "so this process linked a SQLite library that does not encrypt"
                )
            }
            return version
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

    // MARK: - Length conversion and key scanning

    extension AppleStorage {
        /// Convert a bound value's byte count into the `Int32` length SQLite's
        /// bind functions take, and throw when no `Int32` holds that count.
        ///
        /// `Int32(_:)` traps the process for a count above `Int32.max`, so a
        /// `set` of a value that large would terminate the host app. This
        /// method throws `StorageError.databaseError` for that count instead,
        /// and `set` passes that error to its caller.
        ///
        /// - Parameters:
        ///   - count: The number of bytes `binder` is about to hand SQLite.
        ///   - binder: The binding method's name, which the thrown message
        ///     carries.
        /// - Throws: `StorageError.databaseError` when `count` exceeds
        ///   `Int32.max`.
        static func sqliteByteCount(_ count: Int, binder: String) throws -> Int32 {
            guard let byteCount = Int32(exactly: count) else {
                throw StorageError.databaseError(
                    "\(binder) received \(count) bytes, which no Int32 length counts"
                )
            }
            return byteCount
        }

        /// Step `statement` to completion and return the text of its first
        /// column for every row, throwing unless SQLite reports `SQLITE_DONE`.
        ///
        /// `sqlite3_step` answers `SQLITE_BUSY`, `SQLITE_IOERR`, `SQLITE_CORRUPT`,
        /// or another error code when it cannot produce the next row. A loop
        /// that stops on any answer other than `SQLITE_ROW` and returns what it
        /// collected would report a partial key list as a complete one, so this
        /// method reads the answer that ended the loop. `sqlite3_column_text`
        /// answers `NULL` for a `NULL` column and when it runs out of memory,
        /// and the `kv` table's primary key holds no `NULL`, so this method
        /// throws for that answer too rather than skipping a row.
        ///
        /// `String(cString:)` stops at the first zero byte, which would return
        /// `a` for a stored key `a\u{0}b` and would return one string for two
        /// keys that differ only after that byte. `sqlite3_column_bytes`
        /// reports how many bytes SQLite holds for this column, and SQLite's
        /// documentation requires the call order below: read the column
        /// through `sqlite3_column_text` first, then ask for its byte count.
        ///
        /// - Parameter statement: A statement `sqlite3_prepare_v2` produced,
        ///   with every parameter bound, whose first column holds a key.
        /// - Throws: `StorageError.databaseError` when `statement` is `nil`,
        ///   when a step ends with anything other than `SQLITE_ROW` or
        ///   `SQLITE_DONE`, when a row's first column reads `NULL`, and when a
        ///   key's bytes decode as no UTF-8 string.
        static func readKeys(from statement: OpaquePointer?) throws -> [String] {
            guard let statement else {
                throw StorageError.databaseError("readKeys received no prepared statement")
            }
            var keys: [String] = []
            var result = sqlite3_step(statement)
            while result == SQLITE_ROW {
                guard let text = sqlite3_column_text(statement, 0) else {
                    throw StorageError.databaseError(
                        "a key row read NULL: \(errorMessage(for: statement))"
                    )
                }
                let byteCount = Int(sqlite3_column_bytes(statement, 0))
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
                result = sqlite3_step(statement)
            }
            guard result == SQLITE_DONE else {
                throw StorageError.databaseError(errorMessage(for: statement))
            }
            return keys
        }
    }

#endif // os(iOS) || os(macOS)
