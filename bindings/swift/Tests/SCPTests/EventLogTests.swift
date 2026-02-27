import Foundation
import Testing

@testable import SCP

// MARK: - Event Log Tests

/// Tests for the append-only Merkle event log: event type shape, proof
/// generation, proof verification, and checkpoint types.
///
/// These tests validate the Swift ergonomics layer and type shapes. The
/// UniFFI bridge stubs return placeholder errors until SCP-103 ships.
///
/// See ADR-011 (Event Log), ADR-026 (Swift SDK), and story SCP-102.
@Suite("Event Log Tests")
struct EventLogTests {

    // MARK: - Event type shape

    @Test("Event stores all fields correctly")
    func eventFields() {
        let prevHash = Data(repeating: 0x00, count: 32)
        let signature = Data(repeating: 0xFF, count: 64)
        let event = Event(
            eventType: "message_sent",
            actorDid: "did:dht:z6MkActor",
            timestamp: 1_700_000_000,
            sequence: 42,
            payload: Data("hello".utf8),
            prevHash: prevHash,
            signature: signature
        )

        #expect(event.eventType == "message_sent")
        #expect(event.actorDid == "did:dht:z6MkActor")
        #expect(event.timestamp == 1_700_000_000)
        #expect(event.sequence == 42)
        #expect(event.payload == Data("hello".utf8))
        #expect(event.prevHash.count == 32)
        #expect(event.signature.count == 64)
    }

    @Test("Event genesis sentinel has all-zero prevHash")
    func eventGenesisSentinel() {
        let genesisHash = Data(repeating: 0x00, count: 32)
        let event = Event(
            eventType: "context_created",
            actorDid: "did:dht:z6MkCreator",
            timestamp: 1_700_000_000,
            sequence: 0,
            payload: Data(),
            prevHash: genesisHash,
            signature: Data(repeating: 0x01, count: 64)
        )

        #expect(event.sequence == 0)
        #expect(event.prevHash == Data(repeating: 0x00, count: 32))
    }

    @Test("Event is Sendable")
    func eventIsSendable() async {
        let event: any Sendable = Event(
            eventType: "test",
            actorDid: "did:dht:z6MkTest",
            timestamp: 0,
            sequence: 0,
            payload: Data(),
            prevHash: Data(repeating: 0, count: 32),
            signature: Data(repeating: 0, count: 64)
        )
        #expect(event is Event)
    }

    // MARK: - Proof type shape

    @Test("Proof stores leaf index, hash, path, and root")
    func proofFields() {
        let leafHash = Data(repeating: 0xAA, count: 32)
        let root = Data(repeating: 0xBB, count: 32)
        let siblingHash = Data(repeating: 0xCC, count: 32)

        let proof = Proof(
            leafIndex: 5,
            leafHash: leafHash,
            path: [(hash: siblingHash, direction: "left")],
            root: root
        )

        #expect(proof.leafIndex == 5)
        #expect(proof.leafHash == leafHash)
        #expect(proof.path.count == 1)
        #expect(proof.path[0].direction == "left")
        #expect(proof.path[0].hash == siblingHash)
        #expect(proof.root == root)
    }

    @Test("Proof with multi-level path")
    func proofMultiLevelPath() {
        let path: [(hash: Data, direction: String)] = [
            (hash: Data(repeating: 0x01, count: 32), direction: "left"),
            (hash: Data(repeating: 0x02, count: 32), direction: "right"),
            (hash: Data(repeating: 0x03, count: 32), direction: "left"),
        ]
        let proof = Proof(
            leafIndex: 0,
            leafHash: Data(repeating: 0xAA, count: 32),
            path: path,
            root: Data(repeating: 0xFF, count: 32)
        )

        // O(log n) path: 3 levels implies 4-8 leaves
        #expect(proof.path.count == 3)
        #expect(proof.path[1].direction == "right")
    }

    // MARK: - Checkpoint type shape

    @Test("Checkpoint stores all fields correctly")
    func checkpointFields() {
        let merkleRoot = Data(repeating: 0xDD, count: 32)
        let signature = Data(repeating: 0xEE, count: 64)

        let checkpoint = Checkpoint(
            contextId: "ctx-log-001",
            senderDid: "did:dht:z6MkSender",
            eventCount: 100,
            merkleRoot: merkleRoot,
            epoch: 5,
            timestamp: 1_700_000_000,
            signature: signature
        )

        #expect(checkpoint.contextId == "ctx-log-001")
        #expect(checkpoint.senderDid == "did:dht:z6MkSender")
        #expect(checkpoint.eventCount == 100)
        #expect(checkpoint.merkleRoot.count == 32)
        #expect(checkpoint.epoch == 5)
        #expect(checkpoint.timestamp == 1_700_000_000)
        #expect(checkpoint.signature.count == 64)
    }

    @Test("Checkpoint with nil epoch for broadcast contexts")
    func checkpointNilEpoch() {
        let checkpoint = Checkpoint(
            contextId: "ctx-broadcast",
            senderDid: "did:dht:z6MkSender",
            eventCount: 10,
            merkleRoot: Data(repeating: 0xAA, count: 32),
            epoch: nil,
            timestamp: 1_700_000_000,
            signature: Data(repeating: 0xBB, count: 64)
        )
        #expect(checkpoint.epoch == nil)
    }

    @Test("Checkpoint is Sendable")
    func checkpointIsSendable() async {
        let checkpoint: any Sendable = Checkpoint(
            contextId: "ctx",
            senderDid: "did:dht:z6Mk",
            eventCount: 0,
            merkleRoot: Data(repeating: 0, count: 32),
            epoch: nil,
            timestamp: 0,
            signature: Data(repeating: 0, count: 64)
        )
        #expect(checkpoint is Checkpoint)
    }

    // MARK: - EventLog type shape

    @Test("EventLog stores context ID from handle")
    func eventLogContextId() {
        let handle = EventLogHandle(contextId: "ctx-log-test")
        let log = EventLog(handle: handle)
        #expect(log.contextId == "ctx-log-test")
    }

    @Test("EventLog is Sendable")
    func eventLogIsSendable() async {
        let handle = EventLogHandle(contextId: "ctx-sendable")
        let log: any Sendable = EventLog(handle: handle)
        #expect(log is EventLog)
    }

    // MARK: - Append (query — bridge stub error propagation)

    @Test("EventLog query throws bridge error with SCP-ELOG-001")
    func queryThrowsBridgeError() async {
        let handle = EventLogHandle(contextId: "ctx-query")
        let log = EventLog(handle: handle)

        do {
            _ = try await log.query(fromSequence: 0, limit: 10)
            Issue.record("Expected query to throw")
        } catch let error as ScpError {
            if case .validation(_, let code) = error {
                #expect(code == "SCP-ELOG-001")
            } else {
                Issue.record("Expected ScpError.validation, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Prove inclusion (bridge stub error propagation)

    @Test("EventLog proveInclusion throws bridge error with SCP-ELOG-002")
    func proveInclusionThrowsBridgeError() async {
        let handle = EventLogHandle(contextId: "ctx-prove")
        let log = EventLog(handle: handle)

        do {
            _ = try await log.proveInclusion(leafIndex: 0)
            Issue.record("Expected proveInclusion to throw")
        } catch let error as ScpError {
            if case .validation(_, let code) = error {
                #expect(code == "SCP-ELOG-002")
            } else {
                Issue.record("Expected ScpError.validation, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Verify proof (bridge stub error propagation)

    @Test("EventLog verifyInclusion throws bridge error with SCP-ELOG-003")
    func verifyInclusionThrowsBridgeError() async {
        let proof = Proof(
            leafIndex: 0,
            leafHash: Data(repeating: 0xAA, count: 32),
            path: [],
            root: Data(repeating: 0xBB, count: 32)
        )

        do {
            _ = try await EventLog.verifyInclusion(proof)
            Issue.record("Expected verifyInclusion to throw")
        } catch let error as ScpError {
            if case .validation(_, let code) = error {
                #expect(code == "SCP-ELOG-003")
            } else {
                Issue.record("Expected ScpError.validation, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

} // end EventLogTests
