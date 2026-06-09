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

    /// `configureLocalTransport(localDid:)` with a valid DID must succeed,
    /// wiring an in-process loopback transport for E2E flows without a relay.
    func testConfigureLocalTransportSucceedsForValidDid() throws {
        try scp.configureLocalTransport(localDid: "did:key:z6MkfreshLocalTransportTest")
    }

    /// `configureLocalTransport(localDid:)` must reject a malformed DID with a
    /// validation error.
    func testConfigureLocalTransportRejectsInvalidDid() throws {
        XCTAssertThrowsError(
            try scp.configureLocalTransport(localDid: "not-a-valid-did"),
            "malformed DID must be rejected"
        ) { error in
            guard case ScpError.Validation = error else {
                XCTFail("expected ScpError.Validation, got \(error)")
                return
            }
        }
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

    // MARK: - Bridge credential store (spec §12.11)

    /// Full credential lifecycle: provision -> retrieve -> rotate ->
    /// list -> revoke, scoped to this instance's store.
    func testBridgeCredentialLifecycle() throws {
        let bridgeId = "bridge-cred-swift-001"
        let key = Data(repeating: 9, count: 32)

        let provisioned = try scp.bridgeCredentialProvision(
            bridgeId: bridgeId,
            credentialType: "ApiKey",
            plaintext: Data("first-secret".utf8),
            bridgeCredentialKey: key
        )
        XCTAssertEqual(provisioned.bridgeId, bridgeId)
        XCTAssertEqual(provisioned.credentialType, "ApiKey")

        let retrieved = try scp.bridgeCredentialRetrieve(
            bridgeId: bridgeId,
            credentialType: "ApiKey",
            bridgeCredentialKey: key
        )
        XCTAssertEqual(String(bytes: retrieved, encoding: .utf8), "first-secret")

        _ = try scp.bridgeCredentialRotate(
            bridgeId: bridgeId,
            credentialType: "ApiKey",
            newPlaintext: Data("second-secret".utf8),
            bridgeCredentialKey: key
        )
        let rotated = try scp.bridgeCredentialRetrieve(
            bridgeId: bridgeId,
            credentialType: "ApiKey",
            bridgeCredentialKey: key
        )
        XCTAssertEqual(String(bytes: rotated, encoding: .utf8), "second-secret")

        XCTAssertEqual(try scp.bridgeCredentialList(bridgeId: bridgeId), ["ApiKey"])

        try scp.bridgeCredentialRevoke(bridgeId: bridgeId)
        XCTAssertThrowsError(
            try scp.bridgeCredentialRetrieve(
                bridgeId: bridgeId,
                credentialType: "ApiKey",
                bridgeCredentialKey: key
            )
        )
    }

    /// Credential key custody: store -> get -> delete.
    func testBridgeCredentialKeyCustodyLifecycle() throws {
        let bridgeId = "bridge-cred-swift-002"
        let key = Data(repeating: 3, count: 32)

        try scp.bridgeCredentialStoreKey(bridgeId: bridgeId, key: key)
        XCTAssertEqual(try scp.bridgeCredentialGetKey(bridgeId: bridgeId), key)

        try scp.bridgeCredentialDeleteKey(bridgeId: bridgeId)
        XCTAssertThrowsError(try scp.bridgeCredentialGetKey(bridgeId: bridgeId))
    }

    // MARK: - Petname event replay and counts (§22.4, §22.9.2)

    /// `petnameApplyEvent` replays a serialized `PetnameEvent` into the
    /// owner's map; the count queries reflect the resulting state.
    func testPetnameApplyEventAndCounts() throws {
        let owner = "did:dht:zSwiftPetnameApply"

        XCTAssertEqual(try scp.petnameDidCount(ownerDid: owner), 0)
        XCTAssertEqual(try scp.petnameContextCount(ownerDid: owner), 0)

        try scp.petnameApplyEvent(
            ownerDid: owner,
            eventJson: #"{"SetPetname": {"did": "did:dht:zAlice", "name": "alice"}}"#
        )
        XCTAssertEqual(try scp.petnameDidCount(ownerDid: owner), 1)

        try scp.petnameApplyEvent(
            ownerDid: owner,
            eventJson: #"{"SetContextPetname": {"context_id": "ctx-1", "name": "work"}}"#
        )
        XCTAssertEqual(try scp.petnameContextCount(ownerDid: owner), 1)

        try scp.petnameApplyEvent(
            ownerDid: owner,
            eventJson: #"{"RemovePetname": {"did": "did:dht:zAlice"}}"#
        )
        XCTAssertEqual(try scp.petnameDidCount(ownerDid: owner), 0)
        // Removing the DID petname leaves the context petname intact.
        XCTAssertEqual(try scp.petnameContextCount(ownerDid: owner), 1)
    }

    /// An applied `SetPetname` event resolves identically to `petnameSet`,
    /// because both mutate the same backing `PetnameMap`.
    func testPetnameApplyEventMatchesSet() throws {
        let owner = "did:dht:zSwiftPetnameParity"

        try scp.petnameApplyEvent(
            ownerDid: owner,
            eventJson: #"{"SetPetname": {"did": "did:dht:zBob", "name": "bob"}}"#
        )
        let json = try scp.petnameResolveDid(ownerDid: owner, name: "bob")
        let resolved = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String]
        )
        XCTAssertEqual(resolved, ["did:dht:zBob"])
    }

    /// A malformed event JSON is rejected at the bridge boundary with a
    /// validation error.
    func testPetnameApplyEventRejectsMalformedJson() throws {
        XCTAssertThrowsError(
            try scp.petnameApplyEvent(
                ownerDid: "did:dht:zSwiftOwner",
                eventJson: "not-valid-event-json"
            )
        ) { error in
            guard case ScpError.Validation = error else {
                XCTFail("expected ScpError.Validation, got \(error)")
                return
            }
        }
    }

    /// Empty `ownerDid` is rejected for the count queries.
    func testPetnameCountsRejectEmptyOwner() throws {
        XCTAssertThrowsError(try scp.petnameDidCount(ownerDid: "")) { error in
            guard case ScpError.Validation = error else {
                XCTFail("expected ScpError.Validation, got \(error)")
                return
            }
        }
        XCTAssertThrowsError(try scp.petnameContextCount(ownerDid: "")) { error in
            guard case ScpError.Validation = error else {
                XCTFail("expected ScpError.Validation, got \(error)")
                return
            }
        }
    }

    /// A non-empty but syntactically invalid `ownerDid` is rejected by the
    /// pre-existing petname ops, matching the strict DID validation the WASM
    /// bridge and the §4.7 ops already enforce. All four bridges treat the
    /// per-identity petname partition key uniformly as a DID.
    func testPetnameRejectsMalformedOwner() {
        let bad = "not-a-did"
        func assertValidation(_ body: () throws -> Void) {
            XCTAssertThrowsError(try body()) { error in
                guard case ScpError.Validation = error else {
                    XCTFail("expected ScpError.Validation, got \(error)")
                    return
                }
            }
        }
        assertValidation { try self.scp.petnameSet(ownerDid: bad, targetDid: "did:dht:z1", name: "test") }
        assertValidation { try self.scp.petnameRemove(ownerDid: bad, targetDid: "did:dht:z1") }
        assertValidation { try self.scp.petnameSetContext(ownerDid: bad, contextId: "ctx-1", name: "work") }
        assertValidation { try self.scp.petnameRemoveContext(ownerDid: bad, contextId: "ctx-1") }
        assertValidation { _ = try self.scp.petnameResolveDid(ownerDid: bad, name: "alice") }
        assertValidation { _ = try self.scp.petnameResolveContext(ownerDid: bad, name: "work") }
        assertValidation { _ = try self.scp.petnameGetForDid(ownerDid: bad, targetDid: "did:dht:z1") }
        assertValidation { _ = try self.scp.petnameGetForContext(ownerDid: bad, contextId: "ctx-1") }
    }

    /// A petname applied on one instance must not leak into another
    /// (ADR-048 §1 per-instance isolation).
    func testPetnameMapsArePerInstance() throws {
        let owner = "did:dht:zSwiftPetnameIsolation"
        try scp.petnameApplyEvent(
            ownerDid: owner,
            eventJson: #"{"SetPetname": {"did": "did:dht:zCarol", "name": "carol"}}"#
        )
        XCTAssertEqual(try scp.petnameDidCount(ownerDid: owner), 1)

        let other = SCP()
        defer { Task { try? await other.shutdown(timeoutMillis: 1000) } }
        XCTAssertEqual(try other.petnameDidCount(ownerDid: owner), 0)
    }

    /// A credential provisioned on one instance must not be visible on
    /// another (ADR-048 §1 per-instance isolation).
    func testBridgeCredentialStoreIsPerInstance() throws {
        let bridgeId = "bridge-cred-swift-003"
        let key = Data(repeating: 1, count: 32)

        _ = try scp.bridgeCredentialProvision(
            bridgeId: bridgeId,
            credentialType: "ApiKey",
            plaintext: Data("only-in-a".utf8),
            bridgeCredentialKey: key
        )

        let other = SCP()
        defer { Task { try? await other.shutdown(timeoutMillis: 1000) } }
        XCTAssertThrowsError(
            try other.bridgeCredentialRetrieve(
                bridgeId: bridgeId,
                credentialType: "ApiKey",
                bridgeCredentialKey: key
            ),
            "credential provisioned on instance A must not leak into instance B"
        )
    }

    /// An empty receipt batch is the clean supervisor-backed happy path — it
    /// needs no payment adapter, so it exercises the
    /// ``SCP/economyVerifyPaymentReceipts`` forwarder. The path dispatches an
    /// `EconomyCommand` to the supervisor, so a supervisor must be attached
    /// first (mirrors the reference Rust test, which calls
    /// `configure_local_transport` before the empty-batch call). The bridge
    /// returns `{"all_valid":true,"results":[]}` — `all_valid` is vacuously
    /// `true` for an empty batch and `results` is empty.
    func testEconomyVerifyPaymentReceiptsEmptyBatch() async throws {
        try scp.configureLocalTransport(localDid: "did:key:z6MkSwiftVerifyReceiptsEmptyTest")
        let out = try await scp.economyVerifyPaymentReceipts(receiptsJson: "[]")
        XCTAssertEqual(
            out, "{\"all_valid\":true,\"results\":[]}",
            "empty batch must return all_valid=true with an empty results array, got \(out)"
        )
    }
}
