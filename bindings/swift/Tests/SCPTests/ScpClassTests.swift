@testable import SCP
import XCTest

// Tests for the SDK-level `SCP` wrapper class (ADR-048, #1549 Phase 4 PR 1).
//
// These tests require the UniFFI bindings to be regenerated against the
// Phase 4 PR 1 FFI crate — specifically, they need the `Scp` class and its
// `defaultInstance` / `withStorage` / `withPersistence` constructors to be
// present in `Internal/ScpBindings.swift`. Hosted CI regenerates the
// bindings before running tests; in local dev without regeneration the
// tests fail to compile.
//
// Each test constructs a fresh `SCP` and verifies the lifecycle contract.
// `SCP.default()` shares state with the deprecated free-function façade
// (via the process-wide `DEFAULT_BRIDGE_INSTANCE`), so multiple calls
// return distinct wrapper objects with the same `instanceId`.

final class ScpClassTests: XCTestCase {
    /// `SCP()` must construct successfully and expose a non-zero
    /// monotonic `instanceId`.
    func testScpConstructsSuccessfully() {
        let scp = SCP()
        XCTAssertGreaterThan(scp.instanceId, 0, "fresh SCP must have a non-zero monotonic id")
    }

    /// Two fresh `SCP()` objects must have distinct ids.
    func testFreshInstancesHaveDistinctIds() {
        let first = SCP()
        let second = SCP()
        XCTAssertNotEqual(
            first.instanceId,
            second.instanceId,
            "SCP() must allocate fresh instances, not reuse a cached handle"
        )
    }

    /// `SCP.default()` must return the same id on repeated calls.
    func testDefaultInstanceIsStable() throws {
        let first = try SCP.default()
        let second = try SCP.default()
        XCTAssertEqual(
            first.instanceId,
            second.instanceId,
            "SCP.default() must wrap the same underlying Arc across calls"
        )
    }

    /// A fresh `SCP()` must not collide with the default instance.
    func testFreshInstanceDistinctFromDefault() throws {
        let fresh = SCP()
        let defaultInstance = try SCP.default()
        XCTAssertNotEqual(
            fresh.instanceId,
            defaultInstance.instanceId,
            "SCP() must allocate a fresh instance, not reuse the default"
        )
    }

    /// `suspend()` followed by `resume()` must succeed on a fresh
    /// instance.
    ///
    /// `resume()` is `async throws` as of #1678 — UniFFI generates an
    /// async Swift method because the underlying Rust `Scp::resume` is
    /// `pub async fn` (transport reconnect + persisted-context
    /// rehydration happen inside the future).
    func testSuspendResumeRoundtrip() async throws {
        let scp = SCP()
        try scp.suspend()
        try await scp.resume()
    }

    /// `shutdown(timeout:)` must complete within the deadline and
    /// be idempotent on subsequent calls.
    func testShutdownWithTimeout() async throws {
        let scp = SCP()
        try await scp.shutdown(timeout: 1)
        // Second call must not throw — the SDK surface treats
        // AlreadyShutDown as a harmless no-op.
        try await scp.shutdown(timeout: 1)
    }

    /// `withStorage(.inMemory)` must produce a fresh instance with a
    /// non-zero id.
    ///
    /// PR 3 added ``StorageConfig/sqlite(path:key:)`` alongside
    /// ``StorageConfig/inMemory``; the SQLite variant has its own
    /// convenience test below.
    func testWithStorageInMemoryProducesFreshInstance() {
        let scp = SCP.withStorage(.inMemory)
        XCTAssertGreaterThan(scp.instanceId, 0)
    }

    /// `withStorage(sqliteDir:key:)` must open a `SQLCipher`-encrypted
    /// database at `{sqliteDir}/scp.db` and return a fresh bridge
    /// instance. Written to a per-test temporary directory so the test
    /// is hermetic.
    ///
    /// PR 3 (#1260 / #1491).
    func testWithStorageSqliteProducesFreshInstance() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("scp-swift-sqlite-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        // 32 random bytes — `SQLCipher` accepts any length and derives
        // the final key via PBKDF2.
        var keyBytes = [UInt8](repeating: 0, count: 32)
        for idx in keyBytes.indices {
            keyBytes[idx] = UInt8.random(in: 0 ... 255)
        }
        let key = Data(keyBytes)

        let scp = SCP.withStorage(sqliteDir: dir, key: key)
        XCTAssertGreaterThan(scp.instanceId, 0)
    }
}
