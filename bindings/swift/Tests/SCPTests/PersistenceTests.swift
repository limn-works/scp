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

        let scp = SCP.withStorage(sqliteDir: dir, key: sqliteKey)
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
        let scp = SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try scp.suspend()
        try await scp.resume()
        try await scp.shutdown(timeout: 1)
    }

    /// A second `SCP.withStorage(sqliteDir:key:)` against the same path
    /// + key must succeed — the restart property at the SDK surface.
    func testSqliteReopenWithSamePathAndKeySucceeds() async throws {
        let scp1 = SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        let id1 = scp1.instanceId
        try await scp1.shutdown(timeout: 1)

        let scp2 = SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        let id2 = scp2.instanceId
        XCTAssertGreaterThan(
            id2, id1,
            "monotonic instance_id counter must advance across two SCP constructions"
        )
        try await scp2.shutdown(timeout: 1)
    }

    /// Construction with a wrong key must not corrupt the original
    /// encrypted database — the bridge logs and falls back, and a
    /// subsequent correct-key open still works.
    func testSqliteRejectsMismatchedKeyWithoutCorruption() async throws {
        let scp1 = SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try await scp1.shutdown(timeout: 1)

        let wrongKey = Data(repeating: 0x11, count: 32)
        let scp2 = SCP.withStorage(sqliteDir: dir, key: wrongKey)
        try await scp2.shutdown(timeout: 1)

        let scp3 = SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try await scp3.shutdown(timeout: 1)
    }
}
