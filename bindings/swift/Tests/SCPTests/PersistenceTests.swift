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
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

        let scp = try SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try scp.suspend()
        try await scp.resume()
        try await scp.shutdown(timeout: 1)
    }

    /// A second `SCP.withStorage(sqliteDir:key:)` against the same path
    /// + key must succeed — that is the restart property #1549 PR 3
    /// delivers at the SDK surface.
    func testSqliteReopenWithSamePathAndKeySucceeds() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

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

    /// FAIL CLOSED (spec §17.6): opening an existing encrypted DB with a
    /// wrong key must throw — never silently fall back to a fresh in-memory
    /// instance — and must not corrupt the original DB (a subsequent
    /// correct-key open still works).
    func testSqliteWrongKeyFailsClosedWithoutCorruption() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

        // First open with the correct key — creates the encrypted DB.
        let scp1 = try SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try await scp1.shutdown(timeout: 1)

        // Second open with a wrong key must FAIL CLOSED (throw).
        let wrongKey = Data(repeating: 0x11, count: 32)
        do {
            let scp2 = try SCP.withStorage(sqliteDir: dir, key: wrongKey)
            try await scp2.shutdown(timeout: 1)
            XCTFail("wrong-key open must fail closed, not silently fall back")
        } catch {
            // Expected: fail closed.
        }

        // Third open with the correct key — must still succeed (no corruption).
        let scp3 = try SCP.withStorage(sqliteDir: dir, key: sqliteKey)
        try await scp3.shutdown(timeout: 1)
    }

    /// `SCP.withStorage(sqliteDir:passphrase:)` must open/create a SQLCipher
    /// database whose key is derived from a passphrase (Argon2id; spec §17.6),
    /// and reopen the SAME database with the same passphrase across restart.
    func testSqlitePassphraseRoundTrip() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

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
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

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
