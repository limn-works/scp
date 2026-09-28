// Tests for adapter `AppleStorage`, the SQLCipher-backed storage adapter that
// ADR-025, the Apple platform adapter, requires to conform to the UniFFI
// `StorageProvider` callback interface.
//
// These cases run against `AppleStorage` itself, opened at a database file this
// process created under an encryption key this file holds, rather than against
// the in-memory replica in `StorageConformanceTests.swift`. That replica shares
// the schema, the query text, and the two parameter-binding helpers, and it
// shares no other line of the six `AppleStorage` key-value method bodies, so a
// defect in the rest of those six bodies reaches no assertion there.
//
// Three properties these cases pin:
//
// 1. The binding helpers `AppleStorage.bindText(_:to:at:)` and
//    `AppleStorage.bindBlob(_:to:at:)`, through which every `AppleStorage`
//    method binds its parameters, throw when SQLite rejects a bind, and bind
//    an empty value as zero bytes rather than as `NULL`. No case here makes
//    SQLite reject a bind inside one of the six methods. SQLite reports a
//    rejected bind through a return code and leaves that parameter reading
//    `NULL`, and a statement carrying `NULL` where a key
//    belongs still steps to `SQLITE_DONE`: `delete` would remove no row and
//    return, `exists` would answer `false` for a key the database holds, and
//    `get` would answer `nil` for it. Acceptance criterion 5 of ADR-025 in
//    `.docs/adrs/phase-5.md` states that property.
// 2. `set`, `get`, `exists`, and `delete` round-trip values through the real
//    database file, including a value of zero bytes.
// 3. Two keys that differ only after a zero byte name two rows for `set`,
//    `get`, `exists`, `delete`, and `deletePrefix`. `sqlite3_bind_text` reads a
//    negative length as "the bytes up to the first zero byte" and answers
//    `SQLITE_OK` for that bind, so the return code property above rejects
//    nothing there; the byte count each method passes is what separates the
//    two keys. The same acceptance criterion states that property.
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

        @Test("bindText binds an empty string as zero bytes of text rather than as NULL")
        func bindTextBindsEmptyStringAsText() throws {
            // SQLite reads a null pointer as a request to bind `NULL` and still
            // answers `SQLITE_OK`, so this case fails for an implementation that
            // hands `sqlite3_bind_text` a null pointer for an empty string.
            let connection = try makeBareConnection()
            defer { sqlite3_close_v2(connection) }

            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            let sql = "SELECT typeof(?1), length(?1)"
            #expect(sqlite3_prepare_v2(connection, sql, -1, &stmt, nil) == SQLITE_OK)

            try AppleStorage.bindText("", to: stmt, at: 1)
            #expect(sqlite3_step(stmt) == SQLITE_ROW)
            #expect(String(cString: sqlite3_column_text(stmt, 0)) == "text")
            #expect(sqlite3_column_int(stmt, 1) == 0)
        }

        /// `bindText` and `bindBlob` both reach this conversion, so a count
        /// above `Int32.max` throws for either of them where `Int32(_:)` would
        /// terminate the process. A case cannot allocate 2 GiB, so it hands
        /// the conversion the count directly.
        @Test("a byte count above Int32.max throws instead of trapping")
        func byteCountAboveInt32MaxThrows() throws {
            #expect(throws: StorageError.self) {
                _ = try AppleStorage.sqliteByteCount(Int(Int32.max) + 1, binder: "bindBlob")
            }
            #expect(try AppleStorage.sqliteByteCount(Int(Int32.max), binder: "bindBlob") == Int32.max)
        }
    }

    // MARK: - Round-trip tests

    /// Cases that run `AppleStorage`'s key-value methods against a real
    /// database file, which is what shows that reading each bind's return code
    /// left those methods working.
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
            // overwrites the first and `get` answers `[0x02]` for both. Five of
            // the seven assertions below fail for that implementation; a
            // measured run of it recorded those five.
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

            try await fixture.storage.delete(key: first)
            #expect(try await fixture.storage.exists(key: first) == false)
            #expect(try await fixture.storage.exists(key: second) == true)
            #expect(try await fixture.storage.deletePrefix(prefix: "delta") == 1)
        }
    }

#endif // os(iOS) || os(macOS)
