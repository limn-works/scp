// Tests for adapter `AppleStorage`, the SQLCipher-backed `StorageProvider`.
//
// These cases run against `AppleStorage` itself, opened at a database file this
// process created under an encryption key this file holds, rather than against
// the in-memory replica in `StorageConformanceTests.swift`. That replica shares
// the schema, the query text, and the two parameter-binding helpers, and it
// shares no line of the six `StorageProvider` method bodies, so a defect in one
// of those six bodies reaches no assertion there.
//
// Four properties these cases pin:
//
// 1. Every `AppleStorage` method throws when SQLite rejects a parameter bind,
//    and none of them reports a result computed from an unbound parameter.
//    SQLite reports a rejected bind through a return code and leaves that
//    parameter reading `NULL`, and a statement carrying `NULL` where a key
//    belongs still steps to `SQLITE_DONE`: `delete` would remove no row and
//    return, `exists` would answer `false` for a key the database holds, and
//    `get` would answer `nil` for it. Acceptance criterion 5 of ADR-025, the
//    Apple platform adapter, in `.docs/adrs/phase-5.md` states that criterion.
// 2. The six `StorageProvider` methods round-trip values through the real
//    database file, including a value of zero bytes.
// 3. Two keys that differ only after a zero byte name two rows, and `listKeys`
//    returns each of them whole. `sqlite3_bind_text` reads a negative length as
//    "the bytes up to the first zero byte" and answers `SQLITE_OK` for that
//    bind, so the return code property above rejects nothing there; the byte
//    count each method passes is what separates the two keys. The same
//    acceptance criterion states that property.
// 4. No file this storage writes carries a stored value in plaintext, which is
//    the observable behind the same criterion's encryption clause: SQLCipher
//    receives the 32-byte key through `PRAGMA key` before any other operation on
//    the connection, and plain SQLite ignores that pragma without an error.
//
// See ADR-025 in `.docs/adrs/phase-5.md`, and §17.11 and §17.13 of the
// persistence-and-storage spec.

#if os(iOS) || os(macOS)

    import Foundation
    import Testing

    #if canImport(SQLite3)
        import SQLite3
    #endif

    @testable import SCP

    // MARK: - Helpers

    /// A database file this process owns for the duration of one case, together
    /// with the storage opened on it.
    private struct StorageFixture {
        let storage: AppleStorage
        let fileURL: URL

        /// Remove the database file and the two files SQLite's write-ahead log
        /// leaves beside it.
        func removeFiles() {
            let manager = FileManager.default
            for suffix in ["", "-wal", "-shm"] {
                let path = fileURL.path + suffix
                try? manager.removeItem(atPath: path)
            }
        }
    }

    /// Open an `AppleStorage` on a fresh file under the system temporary
    /// directory, encrypted under 32 bytes this function fixes.
    ///
    /// `AppleStorage.open()` reads this device's Keychain, and a `swift test`
    /// host runs outside an app bundle with no Keychain access group, so these
    /// cases call `AppleStorage.open(at:encryptionKey:)` and supply both inputs.
    private func makeStorageFixture() throws -> StorageFixture {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("scp-storage-test-\(UUID().uuidString).db")
        let storage = try AppleStorage.open(
            at: fileURL,
            encryptionKey: Data(repeating: 0x2A, count: 32)
        )
        return StorageFixture(storage: storage, fileURL: fileURL)
    }

    /// Open a bare SQLite connection carrying the `kv` table, for cases that
    /// call `AppleStorage.bindText(_:to:at:)` and
    /// `AppleStorage.bindBlob(_:to:at:)` on a statement they prepared
    /// themselves.
    private func makeBareConnection() throws -> OpaquePointer {
        var handle: OpaquePointer?
        guard sqlite3_open(":memory:", &handle) == SQLITE_OK, let connection = handle else {
            if let opened = handle {
                sqlite3_close_v2(opened)
            }
            throw StorageError.databaseError("could not open an in-memory SQLite connection")
        }
        let sql = """
        CREATE TABLE IF NOT EXISTS kv (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        ) WITHOUT ROWID;
        """
        guard sqlite3_exec(connection, sql, nil, nil, nil) == SQLITE_OK else {
            sqlite3_close_v2(connection)
            throw StorageError.databaseError("could not create the kv table")
        }
        return connection
    }

    // MARK: - Bind-status tests

    /// Cases that pin what `AppleStorage` does when SQLite rejects a bind.
    ///
    /// `sqlite3_bind_text` answers `SQLITE_RANGE` for a parameter index no
    /// statement declares, which is a rejection a case can produce without
    /// exhausting memory and without a key longer than `SQLITE_MAX_LENGTH`.
    /// Every rejection SQLite reports travels the same return code, so a method
    /// that throws for this one throws for `SQLITE_NOMEM` and `SQLITE_TOOBIG`
    /// too.
    struct AppleStorageBindStatusTests {
        @Test("bindText throws when SQLite rejects the bind")
        func bindTextThrowsOnRejectedBind() throws {
            let connection = try makeBareConnection()
            defer { sqlite3_close_v2(connection) }

            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            let sql = "SELECT 1 FROM kv WHERE key = ?1 LIMIT 1"
            #expect(sqlite3_prepare_v2(connection, sql, -1, &stmt, nil) == SQLITE_OK)

            // This statement declares one parameter, so index 2 is out of range
            // and `sqlite3_bind_text` answers `SQLITE_RANGE`.
            #expect(throws: StorageError.self) {
                try AppleStorage.bindText("a-key", to: stmt, at: 2)
            }
        }

        @Test("bindText binds a value SQLite accepts and throws nothing")
        func bindTextAcceptsDeclaredParameter() throws {
            let connection = try makeBareConnection()
            defer { sqlite3_close_v2(connection) }

            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            let sql = "SELECT 1 FROM kv WHERE key = ?1 LIMIT 1"
            #expect(sqlite3_prepare_v2(connection, sql, -1, &stmt, nil) == SQLITE_OK)

            try AppleStorage.bindText("a-key", to: stmt, at: 1)
            #expect(sqlite3_step(stmt) == SQLITE_DONE)
        }

        @Test("bindText throws when it receives no prepared statement")
        func bindTextThrowsWithoutStatement() {
            #expect(throws: StorageError.self) {
                try AppleStorage.bindText("a-key", to: nil, at: 1)
            }
        }

        @Test("bindBlob throws when SQLite rejects the bind")
        func bindBlobThrowsOnRejectedBind() throws {
            let connection = try makeBareConnection()
            defer { sqlite3_close_v2(connection) }

            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            let sql = "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)"
            #expect(sqlite3_prepare_v2(connection, sql, -1, &stmt, nil) == SQLITE_OK)

            #expect(throws: StorageError.self) {
                try AppleStorage.bindBlob(Data([0x01, 0x02]), to: stmt, at: 3)
            }
        }

        @Test("bindBlob throws when it receives no prepared statement")
        func bindBlobThrowsWithoutStatement() {
            #expect(throws: StorageError.self) {
                try AppleStorage.bindBlob(Data([0x01]), to: nil, at: 1)
            }
        }

        @Test("bindBlob binds zero bytes as a blob rather than as NULL")
        func bindBlobBindsEmptyBytesAsBlob() throws {
            // The `kv` table declares `value BLOB NOT NULL`, so an insert that
            // bound `NULL` here would fail its constraint at the step below.
            let connection = try makeBareConnection()
            defer { sqlite3_close_v2(connection) }

            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            let sql = "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)"
            #expect(sqlite3_prepare_v2(connection, sql, -1, &stmt, nil) == SQLITE_OK)

            try AppleStorage.bindText("empty", to: stmt, at: 1)
            try AppleStorage.bindBlob(Data(), to: stmt, at: 2)
            #expect(sqlite3_step(stmt) == SQLITE_DONE)
        }

        @Test("bindText binds every byte of a value carrying a zero byte")
        func bindTextBindsPastAZeroByte() throws {
            // `sqlite3_bind_text` reads a negative length as "the bytes up to
            // the first zero byte" and answers `SQLITE_OK`, so this case fails
            // for an implementation that passes `-1`: SQLite would report 5
            // bytes for a 9-byte value. `length()` counts characters up to the
            // first zero byte for a text value and counts bytes for a blob, so
            // this case casts the parameter to a blob first.
            let connection = try makeBareConnection()
            defer { sqlite3_close_v2(connection) }

            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            let sql = "SELECT length(CAST(?1 AS BLOB))"
            #expect(sqlite3_prepare_v2(connection, sql, -1, &stmt, nil) == SQLITE_OK)

            try AppleStorage.bindText("alpha\u{0}one", to: stmt, at: 1)
            #expect(sqlite3_step(stmt) == SQLITE_ROW)
            #expect(sqlite3_column_int(stmt, 0) == 9)
        }
    }

    // MARK: - Round-trip tests

    /// Cases that run the six `StorageProvider` methods against a real database
    /// file, which is what shows that reading each bind's return code left those
    /// methods working.
    struct AppleStorageRoundTripTests {
        @Test("set then get returns the stored bytes")
        func setThenGetReturnsValue() async throws {
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            try await fixture.storage.set(key: "alpha", value: Data([0x01, 0x02, 0x03]))
            let read = try await fixture.storage.get(key: "alpha")
            #expect(read == Data([0x01, 0x02, 0x03]))
        }

        @Test("get answers nil for a key this database does not hold")
        func getAnswersNilForAbsentKey() async throws {
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            let read = try await fixture.storage.get(key: "absent")
            #expect(read == nil)
        }

        @Test("set then get round-trips a value of zero bytes")
        func setThenGetRoundTripsEmptyValue() async throws {
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            try await fixture.storage.set(key: "empty", value: Data())
            let read = try await fixture.storage.get(key: "empty")
            #expect(read == Data())
        }

        @Test("delete removes the row, and exists reports its absence")
        func deleteRemovesTheRow() async throws {
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            try await fixture.storage.set(key: "beta", value: Data([0x04]))
            #expect(try await fixture.storage.exists(key: "beta") == true)

            try await fixture.storage.delete(key: "beta")
            #expect(try await fixture.storage.exists(key: "beta") == false)
            #expect(try await fixture.storage.get(key: "beta") == nil)
        }

        @Test("listKeys returns the keys carrying a prefix, in lexicographic order")
        func listKeysReturnsSortedPrefixMatches() async throws {
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            try await fixture.storage.set(key: "ctx/z", value: Data([0x01]))
            try await fixture.storage.set(key: "ctx/a", value: Data([0x02]))
            try await fixture.storage.set(key: "other/x", value: Data([0x03]))

            let keys = try await fixture.storage.listKeys(prefix: "ctx/")
            #expect(keys == ["ctx/a", "ctx/z"])
        }

        @Test("listKeys with an empty prefix returns every key")
        func listKeysWithEmptyPrefixReturnsEveryKey() async throws {
            // An empty prefix has no successor, so `listKeys` takes its second
            // branch, which binds one parameter rather than two.
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            try await fixture.storage.set(key: "b", value: Data([0x01]))
            try await fixture.storage.set(key: "a", value: Data([0x02]))

            let keys = try await fixture.storage.listKeys(prefix: "")
            #expect(keys == ["a", "b"])
        }

        @Test("deletePrefix removes the matching keys and counts them")
        func deletePrefixRemovesMatchingKeys() async throws {
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            try await fixture.storage.set(key: "ctx/a", value: Data([0x01]))
            try await fixture.storage.set(key: "ctx/b", value: Data([0x02]))
            try await fixture.storage.set(key: "other/x", value: Data([0x03]))

            let deleted = try await fixture.storage.deletePrefix(prefix: "ctx/")
            #expect(deleted == 2)
            #expect(try await fixture.storage.listKeys(prefix: "") == ["other/x"])
        }

        @Test("deletePrefix with an empty prefix removes every key")
        func deletePrefixWithEmptyPrefixRemovesEveryKey() async throws {
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            try await fixture.storage.set(key: "a", value: Data([0x01]))
            try await fixture.storage.set(key: "b", value: Data([0x02]))

            let deleted = try await fixture.storage.deletePrefix(prefix: "")
            #expect(deleted == 2)
            #expect(try await fixture.storage.listKeys(prefix: "") == [])
        }

        @Test("no database file holds a stored value in plaintext")
        func storedValueNeverAppearsInPlaintextOnDisk() async throws {
            // Acceptance criterion 5 of ADR-025 states that the 32-byte key
            // reaches SQLCipher through `PRAGMA key` before any other operation
            // on the connection. Plain SQLite ignores an unknown pragma without
            // an error, so a build whose `sqlite3_` symbols resolved to the
            // system library rather than to the SQLCipher copy inside
            // `ScpFFI.xcframework` would open, write, and read exactly as this
            // suite's other cases expect, while writing every value to disk in
            // the clear. Reading the bytes back off disk is what separates those
            // two builds.
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            let marker = Data("scp-plaintext-marker".utf8)
            try await fixture.storage.set(key: "marker", value: marker)
            #expect(try await fixture.storage.get(key: "marker") == marker)

            // Write-ahead logging puts a fresh row in `<name>-wal` before a
            // checkpoint moves it into the database file, so both files carry
            // the value at some point and this case reads all three paths.
            for suffix in ["", "-wal", "-shm"] {
                let path = fixture.fileURL.path + suffix
                let bytes = (try? Data(contentsOf: URL(fileURLWithPath: path))) ?? Data()
                #expect(
                    bytes.range(of: marker) == nil,
                    "the file at \(path) carries a stored value in plaintext"
                )
            }
        }

        @Test("set overwrites the value an earlier set stored")
        func setOverwritesAnEarlierValue() async throws {
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            try await fixture.storage.set(key: "gamma", value: Data([0x01]))
            try await fixture.storage.set(key: "gamma", value: Data([0x02, 0x03]))
            #expect(try await fixture.storage.get(key: "gamma") == Data([0x02, 0x03]))
        }

        @Test("two keys that differ only after a zero byte name two rows")
        func keysDifferingAfterAZeroByteNameTwoRows() async throws {
            // An implementation that binds a key as a C string stores both of
            // these under the five-byte key `delta`, so the second `set`
            // overwrites the first, `get` answers `[0x02]` for both, and
            // `listKeys` answers `["delta"]`. Six of the eight assertions below
            // fail for that implementation; a measured run of it recorded those
            // six.
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            let first = "delta\u{0}one"
            let second = "delta\u{0}two"
            try await fixture.storage.set(key: first, value: Data([0x01]))
            try await fixture.storage.set(key: second, value: Data([0x02]))

            #expect(try await fixture.storage.get(key: first) == Data([0x01]))
            #expect(try await fixture.storage.get(key: second) == Data([0x02]))
            #expect(try await fixture.storage.get(key: "delta") == nil)
            #expect(try await fixture.storage.exists(key: "delta") == false)
            #expect(try await fixture.storage.listKeys(prefix: "delta") == [first, second])

            try await fixture.storage.delete(key: first)
            #expect(try await fixture.storage.exists(key: first) == false)
            #expect(try await fixture.storage.exists(key: second) == true)
            #expect(try await fixture.storage.deletePrefix(prefix: "delta") == 1)
        }
    }

#endif // os(iOS) || os(macOS)
