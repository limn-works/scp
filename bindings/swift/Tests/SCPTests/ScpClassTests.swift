@testable import SCP
import XCTest

// Tests for the SDK-level `SCP` wrapper class (ADR-048, #1549 Phase 4).
//
// These tests exercise the per-instance lifecycle — each test gets a fresh
// `SCP` via `setUp`, and `tearDown` shuts it down deterministically so
// tests don't leak runtime state across the suite.
//
// After Phase 4 PR 4 (demolition) there is no `SCP.default()` — every
// caller must construct `SCP()` explicitly.

final class ScpClassTests: XCTestCase {
    // Implicitly unwrapped because XCTest `setUp` initializes it before
    // any test method runs — the XCTest lifecycle guarantees non-nil.
    // swiftlint:disable:next implicitly_unwrapped_optional
    var scp: SCP!

    override func setUp() {
        super.setUp()
        scp = SCP()
    }

    override func tearDown() async throws {
        try await scp.shutdown(timeoutMillis: 1000)
        scp = nil
        try await super.tearDown()
    }

    /// `SCP()` must construct successfully and expose a non-zero
    /// monotonic `instanceId`.
    func testScpConstructsSuccessfully() {
        XCTAssertGreaterThan(scp.instanceId, 0, "fresh SCP must have a non-zero monotonic id")
    }

    /// Two fresh `SCP()` objects must have distinct ids.
    func testFreshInstancesHaveDistinctIds() async throws {
        let second = SCP()
        XCTAssertNotEqual(
            scp.instanceId,
            second.instanceId,
            "SCP() must allocate fresh instances, not reuse a cached handle"
        )
        try await second.shutdown(timeoutMillis: 1000)
    }

    /// `suspend()` followed by `resume()` must succeed on a fresh
    /// instance.
    func testSuspendResumeRoundtrip() async throws {
        try scp.suspend()
        try await scp.resume()
    }

    /// `shutdown(timeout:)` must complete within the deadline and
    /// be idempotent on subsequent calls.
    func testShutdownIsIdempotent() async throws {
        // Already shut down by tearDown; directly exercise a fresh one here.
        let extra = SCP()
        try await extra.shutdown(timeout: 1)
        // Second call must not throw — the SDK surface treats
        // AlreadyShutDown as a harmless no-op.
        try await extra.shutdown(timeout: 1)
    }

    /// `withStorage(.inMemory)` must produce a fresh instance with a
    /// non-zero id.
    ///
    /// PR 3 added ``StorageConfig/sqlite(path:key:)`` alongside
    /// ``StorageConfig/inMemory``; the SQLite variant has its own
    /// convenience test below.
    func testWithStorageInMemoryProducesFreshInstance() async throws {
        let instance = try SCP.withStorage(.inMemory)
        XCTAssertGreaterThan(instance.instanceId, 0)
        try await instance.shutdown(timeoutMillis: 1000)
    }

    /// `withStorage(sqliteDir:key:)` must open a `SQLCipher`-encrypted
    /// database at `{sqliteDir}/scp.db` and return a fresh bridge
    /// instance.
    func testWithStorageSqliteProducesFreshInstance() async throws {
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

        let instance = try SCP.withStorage(sqliteDir: dir, key: key)
        XCTAssertGreaterThan(instance.instanceId, 0)
        try await instance.shutdown(timeoutMillis: 1000)
    }
}
