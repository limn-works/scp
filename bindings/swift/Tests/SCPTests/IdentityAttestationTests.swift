@testable import SCP
import XCTest

/// Tests for identity link attestation wrappers (§3.5).
///
/// Covers:
/// - IdentityAttestation construction and equality
/// - IdentityAttestationBridge defaults throw not-implemented
/// - Public API functions throw not-implemented with correct error codes
/// - IdentityAttestation.verify throws not-implemented
final class IdentityAttestationTests: XCTestCase {
    // MARK: - IdentityAttestation struct tests

    func testConstructionDefaults() {
        let att = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000.0
        )
        XCTAssertEqual(att.id, "abc123")
        XCTAssertEqual(att.platform, "github.com")
        XCTAssertEqual(att.platformHandle, "alice")
        XCTAssertEqual(att.verificationMethod, "did:dht:z6Mk...#active")
        XCTAssertEqual(att.verifiedAt, 1_700_000_000.0)
        XCTAssertEqual(att.revocationStatus, "active")
        XCTAssertNil(att.platformId)
    }

    func testConstructionAllFields() {
        let att = IdentityAttestation(
            id: "def456",
            platform: "x.com",
            platformHandle: "bob",
            verificationMethod: "did:dht:z6Mk...#agent",
            verifiedAt: 1_700_000_000.0,
            revocationStatus: "revoked",
            platformId: "12345"
        )
        XCTAssertEqual(att.revocationStatus, "revoked")
        XCTAssertEqual(att.platformId, "12345")
    }

    func testEquality() {
        let att1 = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000.0
        )
        let att2 = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000.0
        )
        XCTAssertEqual(att1, att2)
    }

    func testInequality() {
        let att1 = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000.0
        )
        let att2 = IdentityAttestation(
            id: "def456",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000.0
        )
        XCTAssertNotEqual(att1, att2)
    }

    // MARK: - Bridge defaults throw not-implemented

    func testCreateThrowsNotImplemented() async {
        do {
            _ = try await createIdentityAttestation(
                did: "did:dht:z6MkTest",
                platform: "github.com",
                handle: "alice",
                proof: "proof123"
            )
            XCTFail("Expected error")
        } catch let error as ScpError {
            switch error {
            case let .Identity(msg, code):
                XCTAssertTrue(msg.contains("not yet available"))
                XCTAssertEqual(code, "SCP-ATTEST-9001")
            default:
                XCTFail("Expected Identity error, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func testListThrowsNotImplemented() async {
        do {
            _ = try await listIdentityAttestations(did: "did:dht:z6MkTest")
            XCTFail("Expected error")
        } catch let error as ScpError {
            switch error {
            case let .Identity(msg, code):
                XCTAssertTrue(msg.contains("not yet available"))
                XCTAssertEqual(code, "SCP-ATTEST-9002")
            default:
                XCTFail("Expected Identity error, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func testRemoveThrowsNotImplemented() async {
        do {
            _ = try await removeIdentityAttestation(
                did: "did:dht:z6MkTest",
                attestationId: "att-123"
            )
            XCTFail("Expected error")
        } catch let error as ScpError {
            switch error {
            case let .Identity(msg, code):
                XCTAssertTrue(msg.contains("not yet available"))
                XCTAssertEqual(code, "SCP-ATTEST-9003")
            default:
                XCTFail("Expected Identity error, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func testRenewThrowsNotImplemented() async {
        do {
            _ = try await renewIdentityAttestation(
                did: "did:dht:z6MkTest",
                attestationId: "att-123"
            )
            XCTFail("Expected error")
        } catch let error as ScpError {
            switch error {
            case let .Identity(msg, code):
                XCTAssertTrue(msg.contains("not yet available"))
                XCTAssertEqual(code, "SCP-ATTEST-9004")
            default:
                XCTFail("Expected Identity error, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func testVerifyThrowsNotImplemented() async {
        let att = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000.0
        )
        do {
            _ = try await att.verify()
            XCTFail("Expected error")
        } catch let error as ScpError {
            switch error {
            case let .Identity(msg, code):
                XCTAssertTrue(msg.contains("not yet available"))
                XCTAssertEqual(code, "SCP-ATTEST-9005")
            default:
                XCTFail("Expected Identity error, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    // MARK: - Custom bridge function injection

    func testCreateWithCustomFn() async throws {
        let expected = IdentityAttestation(
            id: "test-id",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000.0
        )
        let customCreate: IdentityAttestationBridge.CreateFn = { _, _, _, _, _ in
            expected
        }
        let result = try await createIdentityAttestation(
            did: "did:dht:z6MkTest",
            platform: "github.com",
            handle: "alice",
            proof: "proof123",
            createFn: customCreate
        )
        XCTAssertEqual(result, expected)
    }

    func testListWithCustomFn() async throws {
        let expected = [
            IdentityAttestation(
                id: "test-id",
                platform: "github.com",
                platformHandle: "alice",
                verificationMethod: "did:dht:z6Mk...#active",
                verifiedAt: 1_700_000_000.0
            )
        ]
        let customList: IdentityAttestationBridge.ListFn = { _ in expected }
        let result = try await listIdentityAttestations(
            did: "did:dht:z6MkTest",
            listFn: customList
        )
        XCTAssertEqual(result, expected)
    }
}
