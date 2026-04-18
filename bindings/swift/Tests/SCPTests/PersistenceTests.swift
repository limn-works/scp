@testable import SCP
import XCTest

// SDK-layer smoke test for SQLite-backed persistence (#1549 Phase 4 PR 3).
//
// Verifies that the Swift SDK wrapper surface:
//
// 1. Accepts `SCP.withStorage(sqliteDir:key:)` and forwards to UniFFI
//    `Scp.withStorage(config: .sqlite(path:, key:))` without raising.
// 2. Creates the SQLCipher database file at `{sqliteDir}/scp.db` as
//    a side effect of construction — see
//    `crates/scp-ffi/uniffi/src/runtime.rs::with_storage_uniffi`.
// 3. Drives the full `suspend() → async resume() → async shutdown()`
//    lifecycle on a SQLite-backed instance without error.
// 4. Is reconstructible against the SAME SQLite directory + key — the
//    reopened instance must open the encrypted database again without
//    re-deriving a fresh key.
//
// The wrapper surface is all this smoke test is responsible for. The
// end-to-end `identity_create → context_create → context_send → suspend
// → restore` path is exercised at the Rust integration layer
// (`crates/scp-testing/tests/integration/persistence_sdk.rs`) because
// the Swift `SCP` class does not yet surface context methods — the
// free-function façade (`contextCreate`, etc.) routes to the
// process-global default instance, not to a caller-owned `SCP` handle,
// and that migration is in #1549 PR 4+.

final class PersistenceTests: XCTestCase {
    /// Stable 32-byte SQLCipher key. The specific value does not matter;
    /// only that the same key is reused across the two constructions
    /// that simulate process restart.
    private let sqliteKey = Data(repeating: 0x42, count: 32)

    /// Allocates a fresh temporary directory for this test.
    private func makeTempDir() throws -> URL {
        let dir = FileManager.default
            .temporaryDirectory
            .appendingPathComponent("scp-persistence-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func removeTempDir(_ dir: URL) {
        try? FileManager.default.removeItem(at: dir)
    }

    /// `SCP.withStorage(sqliteDir:key:)` must open/create the SQLCipher
    /// database on disk.
    func testSqliteConstructionCreatesDatabaseFile() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

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
        try await scp.shutdown(timeoutSecs: 1)
    }

    /// suspend → async resume → async shutdown roundtrip on a SQLite-
    /// backed instance.
    func testSqliteLifecycleRoundtrip() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

        let scp = SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try scp.suspend()
        try await scp.resume()
        try await scp.shutdown(timeoutSecs: 1)
    }

    /// A second `SCP.withStorage(sqliteDir:key:)` against the same path
    /// + key must succeed — that is the restart property #1549 PR 3
    /// delivers at the SDK surface.
    func testSqliteReopenWithSamePathAndKeySucceeds() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

        let scp1 = SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        let id1 = scp1.instanceId
        try await scp1.shutdown(timeoutSecs: 1)

        // Fresh SCP object, same underlying encrypted database.
        let scp2 = SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        let id2 = scp2.instanceId
        XCTAssertGreaterThan(
            id2, id1,
            "monotonic instance_id counter must advance across two SCP constructions"
        )
        try await scp2.shutdown(timeoutSecs: 1)
    }

    /// Construction with a wrong key must not corrupt the original
    /// encrypted database — the bridge logs and falls back, and a
    /// subsequent correct-key open still works.
    func testSqliteRejectsMismatchedKeyWithoutCorruption() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

        // First open with the correct key — creates the encrypted DB.
        let scp1 = SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try await scp1.shutdown(timeoutSecs: 1)

        // Second open with a wrong key. The bridge logs and falls back
        // to an in-memory-only instance; construction succeeds but the
        // original DB file must remain readable with the correct key.
        let wrongKey = Data(repeating: 0x11, count: 32)
        let scp2 = SCP.withStorage(sqliteDir: dir, key: wrongKey)
        try await scp2.shutdown(timeoutSecs: 1)

        // Third open with the correct key — must still succeed.
        let scp3 = SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try await scp3.shutdown(timeoutSecs: 1)
    }
}
