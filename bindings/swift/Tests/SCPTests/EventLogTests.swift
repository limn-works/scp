import Foundation
@testable import SCP
import Testing

// MARK: - Event Log Tests

/// Tests for the append-only Merkle event log: event type shape, proof
/// generation, proof verification, and checkpoint types.
///
/// UniFFI Event fields: eventType, actorDid, timestamp, payloadJson (String), sequence
/// UniFFI Proof fields: verified (Bool), proofType (String), detailsJson (String)
///
/// Async roundtrip tests inject mock bridge functions to verify the delegation
/// pattern works end-to-end without a real UniFFI binary.
///
/// See ADR-011 (Event Log), ADR-026 (Swift SDK), and story SCP-221.
struct EventLogTests {
    // MARK: - Event type shape (UniFFI struct)

    @Test("Event stores all fields correctly")
    func eventFields() {
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
    func eventIsSendable() {
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
    func checkpointIsSendable() {
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
    func eventLogIsSendable() {
        let handle = EventLogHandle(contextId: "ctx-sendable")
        let log: any Sendable = EventLog(handle: handle)
        #expect(log is EventLog)
    }

    // MARK: - Query via injectable bridge (async roundtrip)

    @Test("EventLog query calls bridge and returns events")
    func queryRoundtrip() async throws {
        let contextHandle = ContextHandle(noPointer: .init())
        let handle = EventLogHandle(contextHandle: contextHandle)

        let mockEvents = [
            Event(
                eventType: "message_sent",
                actorDid: "did:dht:z6MkActor",
                timestamp: 1_700_000_000,
                payloadJson: #"{"content": "test"}"#,
                sequence: 1
            ),
            Event(
                eventType: "message_sent",
                actorDid: "did:dht:z6MkActor",
                timestamp: 1_700_000_001,
                payloadJson: #"{"content": "test2"}"#,
                sequence: 2
            )
        ]

        let mockQuery: EventLogBridge.QueryFn = { _, filterJson in
            let filter = try #require(filterJson)
            #expect(filter.contains("after_sequence"))
            return mockEvents
        }

        let log = EventLog(handle: handle, queryFn: mockQuery)
        let events = try await log.query(fromSequence: 0, limit: 10)

        #expect(events.count == 2)
        #expect(events[0].sequence == 1)
        #expect(events[1].sequence == 2)
    }

    @Test("EventLog query throws when not backed by ContextHandle")
    func queryThrowsWithoutContextHandle() async {
        let handle = EventLogHandle(contextId: "ctx-no-handle")
        let log = EventLog(handle: handle)

        do {
            _ = try await log.query(fromSequence: 0, limit: 10)
            Issue.record("Expected query to throw")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2030")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Prove inclusion via injectable bridge (async roundtrip)

    @Test("EventLog proveInclusion calls bridge and returns proof")
    func proveInclusionRoundtrip() async throws {
        let contextHandle = ContextHandle(noPointer: .init())
        let handle = EventLogHandle(contextHandle: contextHandle)

        let mockProof = Proof(
            verified: true,
            proofType: "inclusion",
            detailsJson: #"{"leaf_index": 5}"#
        )

        let mockVerify: EventLogBridge.VerifyFn = { _, claimJson in
            #expect(claimJson.contains("inclusion"))
            #expect(claimJson.contains("leaf_index"))
            return mockProof
        }

        let log = EventLog(handle: handle, verifyFn: mockVerify)
        let proof = try await log.proveInclusion(leafIndex: 5)

        #expect(proof.verified)
        #expect(proof.proofType == "inclusion")
    }

    @Test("EventLog proveInclusion throws when not backed by ContextHandle")
    func proveInclusionThrowsWithoutContextHandle() async {
        let handle = EventLogHandle(contextId: "ctx-no-handle")
        let log = EventLog(handle: handle)

        do {
            _ = try await log.proveInclusion(leafIndex: 0)
            Issue.record("Expected proveInclusion to throw")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2031")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Verify proof (pure function, no bridge)

    @Test("EventLog verifyInclusion returns proof.verified")
    func verifyInclusionReturnsVerified() async throws {
        let validProof = Proof(verified: true, proofType: "inclusion", detailsJson: "{}")
        let invalidProof = Proof(verified: false, proofType: "inclusion", detailsJson: "{}")

        let validResult = EventLog.verifyInclusion(validProof)
        let invalidResult = EventLog.verifyInclusion(invalidProof)

        #expect(validResult == true)
        #expect(invalidResult == false)
    }
    // MARK: - Checkpoint generation via injectable bridge (async roundtrip)

    @Test("generateEventLogCheckpoint calls bridge and returns checkpoint")
    func checkpointRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        let identity = Identity(noPointer: .init())

        var receivedEpoch: UInt64?

        let mockCheckpoint: EventLogBridge.CheckpointFn = { _, _, epoch in
            receivedEpoch = epoch
            return Checkpoint(
                contextId: "ctx-checkpoint",
                senderDid: "did:dht:z6MkSender",
                eventCount: 50,
                merkleRoot: Data(repeating: 0xAB, count: 32),
                epoch: epoch,
                timestamp: 1_700_000_000,
                signature: Data(repeating: 0xCD, count: 64)
            )
        }

        let checkpoint = try await generateEventLogCheckpoint(
            handle: handle,
            identity: identity,
            epoch: 7,
            checkpointFn: mockCheckpoint
        )

        #expect(checkpoint.contextId == "ctx-checkpoint")
        #expect(checkpoint.senderDid == "did:dht:z6MkSender")
        #expect(checkpoint.eventCount == 50)
        #expect(checkpoint.epoch == 7)
        #expect(checkpoint.merkleRoot.count == 32)
        #expect(checkpoint.signature.count == 64)
        #expect(receivedEpoch == 7)
    }

    @Test("generateEventLogCheckpoint propagates bridge errors")
    func checkpointPropagatesErrors() async throws {
        let handle = ContextHandle(noPointer: .init())
        let identity = Identity(noPointer: .init())

        let mockCheckpoint: EventLogBridge.CheckpointFn = { _, _, _ in
            throw ScpError.Permission(
                message: "event log checkpoint requires key custody",
                code: "SCP-PERM-3008"
            )
        }

        do {
            _ = try await generateEventLogCheckpoint(
                handle: handle,
                identity: identity,
                epoch: 0,
                checkpointFn: mockCheckpoint
            )
            Issue.record("Expected generateEventLogCheckpoint to throw")
        } catch let error as ScpError {
            if case let .Permission(_, code) = error {
                #expect(code == "SCP-PERM-3008")
            } else {
                Issue.record("Expected ScpError.Permission, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("generateEventLogCheckpoint default throws descriptive error")
    func checkpointDefaultThrows() async throws {
        let handle = ContextHandle(noPointer: .init())
        let identity = Identity(noPointer: .init())

        do {
            _ = try await generateEventLogCheckpoint(
                handle: handle,
                identity: identity,
                epoch: 0
            )
            Issue.record("Expected default to throw")
        } catch let error as ScpError {
            if case let .Context(message, code) = error {
                #expect(code == "SCP-CTX-2032")
                #expect(message.contains("not yet available"))
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }
} // end EventLogTests
