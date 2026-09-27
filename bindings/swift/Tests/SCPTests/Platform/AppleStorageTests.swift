// Tests for adapter `AppleStorage`, the SQLCipher-backed `StorageProvider`.
//
// These cases run against `AppleStorage` itself, opened at a database file this
// process created under an encryption key this file holds, rather than against
// the in-memory replica in `StorageConformanceTests.swift`. That replica shares
// the schema, the query text, the two parameter-binding helpers, and
// `AppleStorage.readKeys(from:)`, the row loop behind `listKeys`, and it shares
// no other line of the six `StorageProvider` method bodies, so a defect in the
// rest of those six bodies reaches no assertion there.
//
// Four properties these cases pin:
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

    /// The paths of this process's open file descriptors whose path contains
    /// `name`, read through `fcntl(F_GETPATH)`.
    private func openDescriptors(naming name: String) -> [String] {
        var paths: [String] = []
        for descriptor in 0 ..< getdtablesize() {
            var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            let found = buffer.withUnsafeMutableBytes { raw in
                fcntl(descriptor, F_GETPATH, raw.baseAddress) != -1
            }
            guard found else { continue }
            let path = String(cString: buffer)
            if path.contains(name) {
                paths.append(path)
            }
        }
        return paths
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

    // MARK: - Key-scan tests

    /// Cases that pin how `AppleStorage.readKeys(from:)`, the loop behind
    /// `listKeys`, ends a scan.
    struct AppleStorageKeyScanTests {
        /// `abs` raises SQLite's "integer overflow" error for the smallest
        /// 64-bit integer, so this statement answers `SQLITE_ROW` for `a` and
        /// then an error for `b`. A loop that stops on any answer other than
        /// `SQLITE_ROW` would return `["a"]` as a complete list.
        @Test("readKeys throws when a step ends the scan with an error")
        func readKeysThrowsOnStepError() throws {
            let connection = try makeBareConnection()
            defer { sqlite3_close_v2(connection) }

            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            let sql = """
            SELECT CASE WHEN column1 = 'b' THEN abs(-9223372036854775807 - 1) ELSE column1 END
            FROM (VALUES ('a'), ('b'))
            """
            #expect(sqlite3_prepare_v2(connection, sql, -1, &stmt, nil) == SQLITE_OK)

            #expect(throws: StorageError.self) {
                _ = try AppleStorage.readKeys(from: stmt)
            }
        }

        @Test("readKeys throws when a key row reads NULL")
        func readKeysThrowsOnNullKey() throws {
            let connection = try makeBareConnection()
            defer { sqlite3_close_v2(connection) }

            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            let sql = "SELECT column1 FROM (VALUES ('a'), (NULL))"
            #expect(sqlite3_prepare_v2(connection, sql, -1, &stmt, nil) == SQLITE_OK)

            #expect(throws: StorageError.self) {
                _ = try AppleStorage.readKeys(from: stmt)
            }
        }

        @Test("readKeys returns every key when the scan ends with SQLITE_DONE")
        func readKeysReturnsEveryKey() throws {
            let connection = try makeBareConnection()
            defer { sqlite3_close_v2(connection) }

            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            let sql = "SELECT column1 FROM (VALUES ('a'), ('b'))"
            #expect(sqlite3_prepare_v2(connection, sql, -1, &stmt, nil) == SQLITE_OK)

            #expect(try AppleStorage.readKeys(from: stmt) == ["a", "b"])
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
            // an error, and `open(at:encryptionKey:cipherVersion:)` rejects a
            // plain-SQLite connection because that connection answers
            // `PRAGMA cipher_version` with no row. This case checks the
            // outcome that check exists for, independently of the check: the
            // bytes a stored value leaves on disk do not contain that value.
            let fixture = try makeStorageFixture()
            defer { fixture.removeFiles() }

            let marker = Data("scp-plaintext-marker".utf8)
            try await fixture.storage.set(key: "marker", value: marker)
            #expect(try await fixture.storage.get(key: "marker") == marker)

            // Write-ahead logging puts a fresh row in `<name>-wal` before a
            // checkpoint moves it into the database file, so both files carry
            // the value at some point and this case reads all three paths.
            var bytesRead = 0
            for suffix in ["", "-wal", "-shm"] {
                let path = fixture.fileURL.path + suffix
                guard FileManager.default.fileExists(atPath: path) else { continue }
                let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
                bytesRead += bytes.count
                #expect(
                    bytes.range(of: marker) == nil,
                    "the file at \(path) carries a stored value in plaintext"
                )
            }
            // A case that read no bytes would pass for a plaintext build, so
            // it requires that it searched some bytes. The page `open` writes
            // when it creates the `kv` table meets this check by itself, so the
            // check does not prove the stored row reached any of these files;
            // only the marker search above looks for that row.
            #expect(bytesRead > 0, "no database file held any bytes to search")
        }

        @Test("an open that fails after sqlite3_open leaves no descriptor on the file")
        func failedOpenClosesTheConnection() throws {
            // `AppleStorage` closes its connection in `deinit`, and no instance
            // exists while `open(at:encryptionKey:cipherVersion:)` still runs, so every
            // statement that throws inside `open` must close the connection
            // itself. A file written under one key and reopened under another
            // makes `open` throw at the first statement SQLCipher runs against
            // a page.
            let fileURL: URL = try { () throws -> URL in
                // The fixture's storage goes out of scope when this closure
                // returns, and its `deinit` closes the first connection.
                let fixture = try makeStorageFixture()
                return fixture.fileURL
            }()
            defer {
                for suffix in ["", "-wal", "-shm"] {
                    try? FileManager.default.removeItem(atPath: fileURL.path + suffix)
                }
            }
            #expect(openDescriptors(naming: fileURL.lastPathComponent).isEmpty)

            #expect(throws: StorageError.self) {
                _ = try AppleStorage.open(
                    at: fileURL,
                    encryptionKey: Data(repeating: 0x55, count: 32)
                )
            }
            #expect(
                openDescriptors(naming: fileURL.lastPathComponent).isEmpty,
                "a failed open left a descriptor on the database file"
            )
        }

        @Test("the SQLite library this test process linked answers PRAGMA cipher_version")
        func linkedLibraryReportsSQLCipherVersion() throws {
            let connection = try makeBareConnection()
            defer { sqlite3_close_v2(connection) }
            #expect(try !AppleStorage.sqlCipherVersion(db: connection).isEmpty)
        }

        @Test("open throws and closes the file when the connection reports no SQLCipher version")
        func openRejectsConnectionWithoutSQLCipherVersion() throws {
            // The probe answers the way plain SQLite answers
            // `PRAGMA cipher_version`: with no row. Deleting the version check
            // from `open(at:encryptionKey:cipherVersion:)` makes `open` return
            // storage here, and this case fails.
            let fileURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("scp-storage-test-\(UUID().uuidString).db")
            defer {
                for suffix in ["", "-wal", "-shm"] {
                    try? FileManager.default.removeItem(atPath: fileURL.path + suffix)
                }
            }

            do {
                _ = try AppleStorage.open(
                    at: fileURL,
                    encryptionKey: Data(repeating: 0x2A, count: 32),
                    cipherVersion: { _ in try AppleStorage.requireSQLCipherVersion([]) }
                )
                Issue.record("open returned storage on a connection that reported no SQLCipher version")
            } catch let StorageError.databaseError(message) {
                #expect(message.contains("cipher_version"))
            } catch {
                Issue.record("caught \(error), which is not StorageError.databaseError")
            }
            #expect(
                openDescriptors(naming: fileURL.lastPathComponent).isEmpty,
                "a failed open left a descriptor on the database file"
            )
        }

        @Test("a cipher_version answer with no version rejects the connection")
        func missingSQLCipherVersionThrows() throws {
            // Plain SQLite answers the unknown pragma with no row.
            #expect(throws: StorageError.self) {
                try AppleStorage.requireSQLCipherVersion([])
            }
            #expect(throws: StorageError.self) {
                try AppleStorage.requireSQLCipherVersion([""])
            }
            #expect(try AppleStorage.requireSQLCipherVersion(["4.6.1 community"]) == "4.6.1 community")
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
