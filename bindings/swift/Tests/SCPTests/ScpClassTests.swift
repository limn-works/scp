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
    func testSuspendResumeRoundtrip() throws {
        let scp = SCP()
        try scp.suspend()
        try scp.resume()
    }

    /// `shutdown(timeoutSecs:)` must complete within the deadline and
    /// be idempotent on subsequent calls.
    func testShutdownWithTimeout() async throws {
        let scp = SCP()
        try await scp.shutdown(timeoutSecs: 1)
        // Second call must not throw — the SDK surface treats
        // AlreadyShutDown as a harmless no-op.
        try await scp.shutdown(timeoutSecs: 1)
    }

    /// `withStorage(.inMemory)` must produce a fresh instance with a
    /// non-zero id.
    ///
    /// NOTE: `StorageConfig.inMemory` is the Phase 4 PR 1 surface; PR 3
    /// adds filesystem-backed variants.
    func testWithStorageInMemoryProducesFreshInstance() {
        let scp = SCP.withStorage(.inMemory)
        XCTAssertGreaterThan(scp.instanceId, 0)
    }

    /// `withPersistence()` currently returns a fresh in-memory instance
    /// (placeholder; PR 3 wires real persistence).
    func testWithPersistenceProducesFreshInstance() {
        let scp = SCP.withPersistence()
        XCTAssertGreaterThan(scp.instanceId, 0)
    }
}
