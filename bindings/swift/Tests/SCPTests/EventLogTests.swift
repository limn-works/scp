import Foundation
import Testing

@testable import SCP

// MARK: - Event Log Tests

/// Tests for the append-only Merkle event log: event type shape, proof
/// generation, proof verification, and checkpoint types.
///
/// UniFFI Event fields: eventType, actorDid, timestamp, payloadJson (String), sequence
/// UniFFI Proof fields: verified (Bool), proofType (String), detailsJson (String)
///
/// These tests validate the Swift ergonomics layer and type shapes. The
/// UniFFI bridge stubs return placeholder errors until SCP-103 ships.
///
/// See ADR-011 (Event Log), ADR-026 (Swift SDK), and story SCP-102.
@Suite("Event Log Tests")
struct EventLogTests {

    // MARK: - Event type shape (UniFFI struct)

    @Test("Event stores all fields correctly")
    func eventFields() {
        // UniFFI Event uses payloadJson (String) instead of payload (Data).
        // No prevHash or signature fields in the UniFFI version.
        let event = Event(
            eventType: "message_sent",
            actorDid: "did:dht:z6MkActor",
            timestamp: 1_700_000_000,
            payloadJson: #"{"content": "hello"}"#,
            sequence: 42
        )

        #expect(event.eventType == "message_sent")
        #expect(event.actorDid == "did:dht:z6MkActor")
        #expect(event.timestamp == 1_700_000_000)
        #expect(event.payloadJson == #"{"content": "hello"}"#)
        #expect(event.sequence == 42)
    }

    @Test("Event genesis sentinel has sequence 0")
    func eventGenesisSentinel() {
        let event = Event(
            eventType: "context_created",
            actorDid: "did:dht:z6MkCreator",
            timestamp: 1_700_000_000,
            payloadJson: "{}",
            sequence: 0
        )

        #expect(event.sequence == 0)
    }

    @Test("Event is Sendable")
    func eventIsSendable() async {
        let event: any Sendable = Event(
            eventType: "test",
            actorDid: "did:dht:z6MkTest",
            timestamp: 0,
            payloadJson: "{}",
            sequence: 0
        )
        #expect(event is Event)
    }

    // MARK: - Proof type shape (UniFFI struct)

    @Test("Proof stores verified flag, type, and details JSON")
    func proofFields() {
        // UniFFI Proof: verified (Bool), proofType (String), detailsJson (String)
        let proof = Proof(
            verified: true,
            proofType: "inclusion",
            detailsJson: #"{"leaf_index": 5, "path": [{"hash": "aa", "direction": "left"}]}"#
        )

        #expect(proof.verified)
        #expect(proof.proofType == "inclusion")
        #expect(proof.detailsJson.contains("leaf_index"))
    }

    @Test("Proof unverified")
    func proofUnverified() {
        let proof = Proof(
            verified: false,
            proofType: "inclusion",
            detailsJson: #"{"error": "root mismatch"}"#
        )

        #expect(!proof.verified)
    }

    // MARK: - Checkpoint type shape (hand-written, not UniFFI)

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

    // MARK: - EventLog type shape (hand-written, not UniFFI)

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

    // MARK: - Append (query -- bridge stub error propagation)

    @Test("EventLog query throws bridge error with SCP-ELOG-001")
    func queryThrowsBridgeError() async {
        let handle = EventLogHandle(contextId: "ctx-query")
        let log = EventLog(handle: handle)

        do {
            _ = try await log.query(fromSequence: 0, limit: 10)
            Issue.record("Expected query to throw")
        } catch let error as ScpError {
            if case .Validation(_, let code) = error {
                #expect(code == "SCP-ELOG-001")
            } else {
                Issue.record("Expected ScpError.Validation, got \(error)")
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
            if case .Validation(_, let code) = error {
                #expect(code == "SCP-ELOG-002")
            } else {
                Issue.record("Expected ScpError.Validation, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Verify proof (bridge stub error propagation)

    @Test("EventLog verifyInclusion throws bridge error with SCP-ELOG-003")
    func verifyInclusionThrowsBridgeError() async {
        // UniFFI Proof: verified, proofType, detailsJson
        let proof = Proof(
            verified: false,
            proofType: "inclusion",
            detailsJson: "{}"
        )

        do {
            _ = try await EventLog.verifyInclusion(proof)
            Issue.record("Expected verifyInclusion to throw")
        } catch let error as ScpError {
            if case .Validation(_, let code) = error {
                #expect(code == "SCP-ELOG-003")
            } else {
                Issue.record("Expected ScpError.Validation, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

} // end EventLogTests
