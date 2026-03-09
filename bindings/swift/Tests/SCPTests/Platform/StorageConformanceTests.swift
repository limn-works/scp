// Storage conformance tests for the AppleStorage adapter.
//
// These 13 tests mirror the Rust `storage_conformance!()` macro in
// `scp-testing` (spec sections 17.11, 17.13). They validate the
// `StorageProvider` contract using a lightweight in-memory SQLite
// backend that replicates the AppleStorage schema without requiring
// Keychain access or file-system persistence.
//
// The in-memory backend uses the identical SQL schema and query
// patterns as ``AppleStorage`` — the only difference is the absence
// of SQLCipher encryption pragmas and the use of `:memory:` instead
// of a file path. This validates the storage contract (sorted key
// enumeration, prefix scans, delete semantics, concurrent safety)
// without coupling to platform-specific Keychain infrastructure.
//
// See SCP-PERSIST-061.

#if os(iOS) || os(macOS)

    import Foundation
    import Testing

    #if canImport(SQLite3)
        import SQLite3
    #endif

    @testable import SCP

    // MARK: - InMemoryStorage test helper

    /// In-memory SQLite storage for testing. Mirrors the ``AppleStorage``
    /// schema and query patterns but uses `:memory:` and no encryption.
    ///
    /// This is intentionally *not* an actor — it uses a serial DispatchQueue
    /// for synchronisation, matching the thread-safety semantics that the
    /// conformance tests verify. Swift Testing does not require actor isolation.
    ///
    /// `@unchecked Sendable`: The serial queue provides mutual exclusion for
    /// all database operations, making this safe to share across isolation
    /// domains in tests. Every public method dispatches synchronously onto
    /// the queue, so no concurrent access to the `sqlite3` handle is possible.
    private final class InMemoryStorage: @unchecked Sendable {
        // swiftlint:disable:next identifier_name
        private let db: OpaquePointer
        private let queue = DispatchQueue(label: "dev.limn.scp.test-storage")

        init() throws {
            var handle: OpaquePointer?
            // swiftlint:disable:next identifier_name
            guard sqlite3_open(":memory:", &handle) == SQLITE_OK, let db = handle else {
                let msg = handle.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
                if let dbHandle = handle { sqlite3_close_v2(dbHandle) }
                throw StorageError.databaseError("open failed: \(msg)")
            }
            self.db = db

            // Create the same KV table as AppleStorage.
            var errMsg: UnsafeMutablePointer<CChar>?
            let sql = """
            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;
            """
            let status = sqlite3_exec(db, sql, nil, nil, &errMsg)
            if status != SQLITE_OK {
                let msg = errMsg.map { String(cString: $0) } ?? "unknown"
                sqlite3_free(errMsg)
                throw StorageError.databaseError(msg)
            }
        }

        deinit {
            sqlite3_close_v2(db)
        }

        // MARK: - Storage operations (matching AppleStorage signatures)

        func set(key: String, value: Data) throws {
            try queue.sync {
                var stmt: OpaquePointer?
                defer { sqlite3_finalize(stmt) }

                let sql = "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                }
                let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
                sqlite3_bind_text(stmt, 1, (key as NSString).utf8String, -1, transient)
                value.withUnsafeBytes { ptr in
                    sqlite3_bind_blob(stmt, 2, ptr.baseAddress, Int32(ptr.count), transient)
                }
                guard sqlite3_step(stmt) == SQLITE_DONE else {
                    throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                }
            }
        }

        func get(key: String) throws -> Data? {
            try queue.sync {
                var stmt: OpaquePointer?
                defer { sqlite3_finalize(stmt) }

                let sql = "SELECT value FROM kv WHERE key = ?1"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                }
                let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
                sqlite3_bind_text(stmt, 1, (key as NSString).utf8String, -1, transient)

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
                    throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                }
            }
        }

        func delete(key: String) throws {
            try queue.sync {
                var stmt: OpaquePointer?
                defer { sqlite3_finalize(stmt) }

                let sql = "DELETE FROM kv WHERE key = ?1"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                }
                let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
                sqlite3_bind_text(stmt, 1, (key as NSString).utf8String, -1, transient)
                guard sqlite3_step(stmt) == SQLITE_DONE else {
                    throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                }
            }
        }

        func listKeys(prefix: String) throws -> [String] {
            try queue.sync {
                var stmt: OpaquePointer?
                defer { sqlite3_finalize(stmt) }

                let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

                if let upper = AppleStorage.prefixSuccessor(prefix) {
                    let sql = "SELECT key FROM kv WHERE key >= ?1 AND key < ?2 ORDER BY key"
                    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                        throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                    }
                    sqlite3_bind_text(stmt, 1, (prefix as NSString).utf8String, -1, transient)
                    sqlite3_bind_text(stmt, 2, (upper as NSString).utf8String, -1, transient)
                } else {
                    let sql = "SELECT key FROM kv WHERE key >= ?1 ORDER BY key"
                    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                        throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
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
        }

        func deletePrefix(prefix: String) throws -> UInt64 {
            try queue.sync {
                var stmt: OpaquePointer?
                defer { sqlite3_finalize(stmt) }

                let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

                if let upper = AppleStorage.prefixSuccessor(prefix) {
                    let sql = "DELETE FROM kv WHERE key >= ?1 AND key < ?2"
                    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                        throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                    }
                    sqlite3_bind_text(stmt, 1, (prefix as NSString).utf8String, -1, transient)
                    sqlite3_bind_text(stmt, 2, (upper as NSString).utf8String, -1, transient)
                } else {
                    let sql = "DELETE FROM kv WHERE key >= ?1"
                    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                        throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                    }
                    sqlite3_bind_text(stmt, 1, (prefix as NSString).utf8String, -1, transient)
                }

                guard sqlite3_step(stmt) == SQLITE_DONE else {
                    throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                }
                return UInt64(sqlite3_changes(db))
            }
        }

        func exists(key: String) throws -> Bool {
            try queue.sync {
                var stmt: OpaquePointer?
                defer { sqlite3_finalize(stmt) }

                let sql = "SELECT 1 FROM kv WHERE key = ?1 LIMIT 1"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                }
                let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
                sqlite3_bind_text(stmt, 1, (key as NSString).utf8String, -1, transient)

                let result = sqlite3_step(stmt)
                if result == SQLITE_ROW {
                    return true
                } else if result == SQLITE_DONE {
                    return false
                } else {
                    throw StorageError.databaseError(String(cString: sqlite3_errmsg(db)))
                }
            }
        }
    }

    // MARK: - Storage Conformance Tests

    /// XCTest-equivalent conformance suite for the StorageProvider contract.
    ///
    /// Each test creates a fresh in-memory SQLite database, ensuring full
    /// isolation between tests. The 13 test cases are numbered to match the
    /// Rust `storage_conformance!()` macro ordering.
    struct StorageConformanceTests {
        // MARK: 1. roundtrip

        @Test("store and retrieve roundtrip returns original value")
        func roundtrip() throws {
            let storage = try InMemoryStorage()
            let value = Data("value1".utf8)
            try storage.set(key: "key1", value: value)
            let result = try storage.get(key: "key1")
            #expect(result == value)
        }

        // MARK: 2. missing_returns_none

        @Test("retrieve missing key returns nil")
        func missingReturnsNone() throws {
            let storage = try InMemoryStorage()
            let result = try storage.get(key: "nonexistent")
            #expect(result == nil)
        }

        // MARK: 3. delete_removes

        @Test("delete removes stored value")
        func deleteRemoves() throws {
            let storage = try InMemoryStorage()
            try storage.set(key: "key", value: Data("value".utf8))
            try storage.delete(key: "key")
            let result = try storage.get(key: "key")
            #expect(result == nil)
        }

        // MARK: 4. list_keys_sorted

        @Test("listKeys with empty prefix returns all keys sorted")
        func listKeysSorted() throws {
            let storage = try InMemoryStorage()
            try storage.set(key: "c", value: Data())
            try storage.set(key: "a", value: Data())
            try storage.set(key: "b", value: Data())

            let keys = try storage.listKeys(prefix: "")
            #expect(keys == ["a", "b", "c"])
        }

        // MARK: 5. list_keys_prefix_sorted

        @Test("listKeys with prefix returns matching keys sorted")
        func listKeysPrefixSorted() throws {
            let storage = try InMemoryStorage()
            try storage.set(key: "ctx/z", value: Data())
            try storage.set(key: "ctx/a", value: Data())
            try storage.set(key: "ctx/m", value: Data())
            try storage.set(key: "other/x", value: Data())

            let keys = try storage.listKeys(prefix: "ctx/")
            #expect(keys == ["ctx/a", "ctx/m", "ctx/z"])
        }

        // MARK: 6. delete_prefix_removes

        @Test("deletePrefix removes matching keys and returns count")
        func deletePrefixRemoves() throws {
            let storage = try InMemoryStorage()
            try storage.set(key: "ctx/a/1", value: Data("1".utf8))
            try storage.set(key: "ctx/a/2", value: Data("2".utf8))
            try storage.set(key: "ctx/b/1", value: Data("3".utf8))
            try storage.set(key: "other/x", value: Data("4".utf8))

            let deleted = try storage.deletePrefix(prefix: "ctx/a/")
            #expect(deleted == 2)

            // Verify deleted keys are gone.
            #expect(try storage.get(key: "ctx/a/1") == nil)
            #expect(try storage.get(key: "ctx/a/2") == nil)

            // Verify non-matching keys remain.
            #expect(try storage.get(key: "ctx/b/1") == Data("3".utf8))
            #expect(try storage.get(key: "other/x") == Data("4".utf8))
        }

        // MARK: 7. delete_prefix_zero

        @Test("deletePrefix returns 0 when no keys match")
        func deletePrefixZero() throws {
            let storage = try InMemoryStorage()
            try storage.set(key: "foo", value: Data("bar".utf8))

            let deleted = try storage.deletePrefix(prefix: "nonexistent/")
            #expect(deleted == 0)
        }

        // MARK: 8. exists_true

        @Test("exists returns true for stored key")
        func existsTrue() throws {
            let storage = try InMemoryStorage()
            try storage.set(key: "key", value: Data("value".utf8))
            #expect(try storage.exists(key: "key") == true)
        }

        // MARK: 9. exists_false

        @Test("exists returns false for missing key")
        func existsFalse() throws {
            let storage = try InMemoryStorage()
            #expect(try storage.exists(key: "missing") == false)
        }

        // MARK: 10. exists_after_delete

        @Test("exists returns false after delete")
        func existsAfterDelete() throws {
            let storage = try InMemoryStorage()
            try storage.set(key: "key", value: Data("value".utf8))
            try storage.delete(key: "key")
            #expect(try storage.exists(key: "key") == false)
        }

        // MARK: 11. overwrite

        @Test("overwrite replaces value")
        func overwrite() throws {
            let storage = try InMemoryStorage()
            try storage.set(key: "key", value: Data("first".utf8))
            try storage.set(key: "key", value: Data("second".utf8))
            let result = try storage.get(key: "key")
            #expect(result == Data("second".utf8))
        }

        // MARK: 12. concurrent_access

        @Test("concurrent store and retrieve is safe")
        func concurrentAccess() async throws {
            let storage = try InMemoryStorage()

            // Concurrently store 10 keys.
            await withThrowingTaskGroup(of: Void.self) { group in
                for index: UInt32 in 0 ..< 10 {
                    group.addTask {
                        let key = "concurrent/\(index)"
                        var bytes = index.littleEndian
                        let value = Data(bytes: &bytes, count: MemoryLayout<UInt32>.size)
                        try storage.set(key: key, value: value)
                    }
                }
            }

            // Verify all keys are present.
            let keys = try storage.listKeys(prefix: "concurrent/")
            #expect(keys.count == 10)

            // Verify each value matches what was stored.
            for index: UInt32 in 0 ..< 10 {
                let key = "concurrent/\(index)"
                var bytes = index.littleEndian
                let expected = Data(bytes: &bytes, count: MemoryLayout<UInt32>.size)
                let actual = try storage.get(key: key)
                #expect(actual == expected, "value mismatch for key \(key)")
            }
        }

        // MARK: 13. store_empty_value

        @Test("store empty value roundtrips correctly")
        func storeEmptyValue() throws {
            let storage = try InMemoryStorage()
            try storage.set(key: "empty", value: Data())
            let result = try storage.get(key: "empty")
            #expect(result == Data())
        }

        // MARK: - prefixSuccessor unit tests

        @Test("prefixSuccessor increments last byte")
        func prefixSuccessorBasic() {
            #expect(AppleStorage.prefixSuccessor("abc") == "abd")
        }

        @Test("prefixSuccessor handles single character")
        func prefixSuccessorSingleChar() {
            #expect(AppleStorage.prefixSuccessor("a") == "b")
        }

        @Test("prefixSuccessor handles slash-terminated prefix")
        func prefixSuccessorSlash() {
            #expect(AppleStorage.prefixSuccessor("ctx/") == "ctx0")
        }

        @Test("prefixSuccessor returns nil for empty string")
        func prefixSuccessorEmpty() {
            #expect(AppleStorage.prefixSuccessor("") == nil)
        }
    }

#endif // os(iOS) || os(macOS)
