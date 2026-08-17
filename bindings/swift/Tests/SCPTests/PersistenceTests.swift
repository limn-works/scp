@testable import SCP
import XCTest

// SDK-layer smoke test for SQLite-backed persistence (#1549 Phase 4 PR 3).
//
// Verifies that the Swift SDK wrapper surface:
//
// 1. Accepts `SCP.withStorage(sqliteDir:key:)` and forwards to UniFFI
//    `Scp.withStorage(config: .sqlite(path:, key:))` without raising.
// 2. Creates the SQLCipher database file at `{sqliteDir}/scp.db` as
//    a side effect of construction.
// 3. Drives the full `suspend() → async resume() → async shutdown()`
//    lifecycle on a SQLite-backed instance without error.
// 4. Is reconstructible against the SAME SQLite directory + key — the
//    reopened instance must open the encrypted database again without
//    re-deriving a fresh key.
//
// Each test owns a fresh temporary directory via setUp/tearDown so the
// suite is hermetic and can be run in parallel.

final class PersistenceTests: XCTestCase {
    /// Stable 32-byte SQLCipher key for this suite.
    private let sqliteKey = Data(repeating: 0x42, count: 32)

    // Temp directory allocated fresh in `setUp`.
    // swiftlint:disable:next implicitly_unwrapped_optional
    private var dir: URL!

    override func setUp() {
        super.setUp()
        dir = FileManager.default
            .temporaryDirectory
            .appendingPathComponent("scp-persistence-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        if let dir {
            try? FileManager.default.removeItem(at: dir)
        }
        dir = nil
        try await super.tearDown()
    }

    /// `SCP.withStorage(sqliteDir:key:)` must open/create the SQLCipher
    /// database on disk.
    func testSqliteConstructionCreatesDatabaseFile() async throws {
        let dbPath = dir.appendingPathComponent("scp.db")
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: dbPath.path),
            "scp.db must not exist before SCP.withStorage(sqliteDir:key:)"
        )

        let scp = try SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: dbPath.path),
            "SCP.withStorage(sqliteDir:key:) must create scp.db at \(dbPath.path)"
        )
        XCTAssertGreaterThan(scp.instanceId, 0)
        try await scp.shutdown(timeout: 1)
    }

    /// suspend → async resume → async shutdown roundtrip on a SQLite-
    /// backed instance.
    func testSqliteLifecycleRoundtrip() async throws {
        let scp = try SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try scp.suspend()
        try await scp.resume()
        try await scp.shutdown(timeout: 1)
    }

    /// A second `SCP.withStorage(sqliteDir:key:)` against the same path
    /// + key must succeed — the restart property at the SDK surface.
    func testSqliteReopenWithSamePathAndKeySucceeds() async throws {
        let scp1 = try SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        let id1 = scp1.instanceId
        try await scp1.shutdown(timeout: 1)

        // Fresh SCP object, same underlying encrypted database.
        let scp2 = try SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        let id2 = scp2.instanceId
        XCTAssertGreaterThan(
            id2, id1,
            "monotonic instance_id counter must advance across two SCP constructions"
        )
        try await scp2.shutdown(timeout: 1)
    }

    /// Construction with a wrong key must surface a validation error
    /// (SCP-STORAGE-8001) rather than silently succeeding with an empty
    /// in-memory instance — guards against silent downgrade where the
    /// caller would lose access to persisted state. The `UniFFI` bridge
    /// surfaces the `SQLCipher` key-mismatch as `ScpError` rather than
    /// falling back to in-memory. The original encrypted DB must survive
    /// the failed attempt so a subsequent correct-key open still works.
    func testSqliteRejectsMismatchedKeyWithoutCorruption() async throws {
        // First open with the correct key — creates the encrypted DB.
        let scp1 = try SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try await scp1.shutdown(timeout: 1)

        // Second open with a wrong key MUST throw — `SqliteStorage::new`
        // fails at the `PRAGMA key` / WAL-mode step because `SQLCipher`
        // rejects the key as "file is not a database". The `UniFFI`
        // bridge propagates that through `ScpError::Validation`.
        let wrongKey = Data(repeating: 0x11, count: 32)
        XCTAssertThrowsError(
            try SCP.withStorage(sqliteDir: dir, key: wrongKey),
            "mismatched-key construction must throw, not silently fall back"
        )

        // Third open with the correct key — must still succeed, proving
        // the failed mismatched-key attempt did not corrupt or truncate
        // the encrypted database file.
        let scp3 = try SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try await scp3.shutdown(timeout: 1)
    }

    /// `SCP.withStorage(sqliteDir:passphrase:)` must open/create a SQLCipher
    /// database whose key is derived from a passphrase (Argon2id; spec §17.6),
    /// and reopen the SAME database with the same passphrase across restart.
    func testSqlitePassphraseRoundTrip() async throws {
        let dbPath = dir.appendingPathComponent("scp.db")
        let scp1 = try SCP.withStorage(
            sqliteDir: dir, passphrase: "correct horse battery staple"
        )
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: dbPath.path),
            "passphrase construction must create scp.db"
        )
        try await scp1.shutdown(timeout: 1)

        // Reopen with the SAME passphrase — must succeed (salt sidecar
        // re-derives the same key).
        let scp2 = try SCP.withStorage(
            sqliteDir: dir, passphrase: "correct horse battery staple"
        )
        XCTAssertGreaterThan(scp2.instanceId, 0)
        try await scp2.shutdown(timeout: 1)
    }

    /// FAIL CLOSED (spec §17.6): reopening a passphrase-protected DB with the
    /// WRONG passphrase must throw — never silently open a fresh DB.
    func testSqliteWrongPassphraseFailsClosed() async throws {
        let scp1 = try SCP.withStorage(sqliteDir: dir, passphrase: "the-right-one")
        try await scp1.shutdown(timeout: 1)

        do {
            let scp2 = try SCP.withStorage(sqliteDir: dir, passphrase: "the-WRONG-one")
            try await scp2.shutdown(timeout: 1)
            XCTFail("wrong passphrase must fail closed, not silently open a fresh DB")
        } catch {
            // Expected: fail closed.
        }
    }
}
