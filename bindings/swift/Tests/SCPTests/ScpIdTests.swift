@testable import SCP
import Testing

// MARK: - SCPID Tests

// Tests for the SCPID authentication wrappers verifying challenge generation,
// response signing, verification roundtrip, bridge delegation, and error
// propagation through the injectable bridge pattern.
//
// Uses mock bridge functions (injectable closures) to test the SDK layer
// without requiring the Rust binary. The bridge functions return JSON strings
// matching the Rust bridge output format; the SDK layer parses them into
// typed Swift structs.
//
// See spec section 3.11 (SCPID) and ADR-039 (Shared-DID Agent Binding).

struct ScpIdTests {
    // MARK: - Mock Identity

    /// Mock subclass of the UniFFI-generated `Identity` class for testing.
    private final class MockIdentity: Identity, @unchecked Sendable {
        let mockDid: String

        init(did: String) {
            mockDid = did
            super.init(noPointer: .init())
        }

        required init(unsafeFromRawPointer pointer: UnsafeMutableRawPointer) {
            mockDid = ""
            super.init(unsafeFromRawPointer: pointer)
        }

        override func did() -> String {
            mockDid
        }
    }

    // MARK: - Test Data

    private static let testChallengeJson = """
    {\
    "protocol":"scpid/1.0",\
    "nonce":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",\
    "audience":"https://app.example.com",\
    "issued_at":1700000000000,\
    "expires_at":1700000300000\
    }
    """

    private static let testResponseJson = """
    {\
    "protocol":"scpid/1.0",\
    "did":"did:dht:z6MkTestSigner",\
    "signing_key_id":"#active",\
    "nonce":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",\
    "audience":"https://app.example.com",\
    "signed_at":1700000000500,\
    "signature":"\
    aabbccddee00112233445566778899aabbccddee00112233445566778899aabbccddee\
    00112233445566778899aabbccddee00112233445566778899aabbccdd\
    "\
    }
    """

    private static let testAuthJson = """
    {\
    "did":"did:dht:z6MkTestSigner",\
    "signing_key_id":"#active",\
    "signed_at":1700000000500\
    }
    """

    // MARK: - Challenge Tests

    @Test("ScpId.challenge calls bridge with correct arguments")
    func challengeCallsBridgeWithCorrectArgs() throws {
        var receivedAudience: String?
        var receivedTtl: UInt64?
        let mockChallenge: ScpId.ChallengeFn = { audience, ttlSeconds in
            receivedAudience = audience
            receivedTtl = ttlSeconds
            return ScpIdTests.testChallengeJson
        }

        let result = try ScpId.challenge(
            audience: "https://app.example.com",
            ttl: 60,
            challengeFn: mockChallenge
        )

        #expect(receivedAudience == "https://app.example.com")
        #expect(receivedTtl == 60)
        #expect(result.protocolVersion == "scpid/1.0")
        #expect(result.audience == "https://app.example.com")
        #expect(result.issuedAt == 1_700_000_000_000)
        #expect(result.expiresAt == 1_700_000_300_000)
        #expect(!result.nonce.isEmpty)
        #expect(!result.json.isEmpty)
    }

    @Test("ScpId.challenge uses default TTL of 300 seconds")
    func challengeUsesDefaultTtl() throws {
        var receivedTtl: UInt64?
        let mockChallenge: ScpId.ChallengeFn = { _, ttlSeconds in
            receivedTtl = ttlSeconds
            return ScpIdTests.testChallengeJson
        }

        _ = try ScpId.challenge(
            audience: "https://app.example.com",
            challengeFn: mockChallenge
        )

        #expect(receivedTtl == 300)
    }

    @Test("ScpId.challenge propagates bridge errors")
    func challengePropagatesBridgeErrors() throws {
        let mockChallenge: ScpId.ChallengeFn = { _, _ in
            throw ScpError.Validation(
                msg: "audience must not be empty",
                code: "SCP-IDENT-1038"
            )
        }

        do {
            _ = try ScpId.challenge(
                audience: "",
                challengeFn: mockChallenge
            )
            Issue.record("Expected ScpId.challenge to throw")
        } catch let error as ScpError {
            if case let .Validation(message, code) = error {
                #expect(code == "SCP-IDENT-1038")
                #expect(message.contains("audience"))
            } else {
                Issue.record("Expected ScpError.Validation, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Sign Tests

    @Test("ScpId.sign calls bridge with correct arguments")
    func signCallsBridgeWithCorrectArgs() throws {
        let identity = MockIdentity(did: "did:dht:z6MkTestSigner")
        var receivedIdentity: Identity?
        var receivedKeyId: String?
        var receivedChallengeJson: String?

        let mockSign: ScpId.SignFn = { ident, keyId, challengeJson in
            receivedIdentity = ident
            receivedKeyId = keyId
            receivedChallengeJson = challengeJson
            return ScpIdTests.testResponseJson
        }

        let challenge = try ScpId.challenge(
            audience: "https://app.example.com",
            challengeFn: { _, _ in ScpIdTests.testChallengeJson }
        )

        let response = try ScpId.sign(
            identity: identity,
            signingKeyId: "#active",
            challenge: challenge,
            signFn: mockSign
        )

        #expect(receivedIdentity?.did() == "did:dht:z6MkTestSigner")
        #expect(receivedKeyId == "#active")
        #expect(receivedChallengeJson == challenge.json)
        #expect(response.did == "did:dht:z6MkTestSigner")
        #expect(response.signingKeyId == "#active")
        #expect(response.audience == "https://app.example.com")
        #expect(!response.json.isEmpty)
    }

    @Test("ScpId.sign propagates bridge errors for missing agent key")
    func signPropagatesErrors() throws {
        let identity = MockIdentity(did: "did:dht:z6MkNoAgentKey")

        let mockSign: ScpId.SignFn = { _, _, _ in
            throw ScpError.Identity(
                msg: "identity has no agent signing key",
                code: "SCP-IDENT-1034"
            )
        }

        let challenge = try ScpId.challenge(
            audience: "https://app.example.com",
            challengeFn: { _, _ in ScpIdTests.testChallengeJson }
        )

        do {
            _ = try ScpId.sign(
                identity: identity,
                signingKeyId: "#agent",
                challenge: challenge,
                signFn: mockSign
            )
            Issue.record("Expected ScpId.sign to throw")
        } catch let error as ScpError {
            if case let .Identity(message, code) = error {
                #expect(code == "SCP-IDENT-1034")
                #expect(message.contains("agent signing key"))
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Verify Tests

    @Test("ScpId.verify calls bridge and returns authentication result")
    func verifyRoundtrip() throws {
        var receivedResponseJson: String?
        var receivedChallengeJson: String?

        let mockVerify: ScpId.VerifyFn = { responseJson, challengeJson in
            receivedResponseJson = responseJson
            receivedChallengeJson = challengeJson
            return ScpIdTests.testAuthJson
        }

        let challenge = try ScpId.challenge(
            audience: "https://app.example.com",
            challengeFn: { _, _ in ScpIdTests.testChallengeJson }
        )
        let response = try ScpId.sign(
            identity: MockIdentity(did: "did:dht:z6MkTestSigner"),
            signingKeyId: "#active",
            challenge: challenge,
            signFn: { _, _, _ in ScpIdTests.testResponseJson }
        )

        let auth = try ScpId.verify(
            response: response,
            challenge: challenge,
            verifyFn: mockVerify
        )

        #expect(receivedResponseJson == response.json)
        #expect(receivedChallengeJson == challenge.json)
        #expect(auth.did == "did:dht:z6MkTestSigner")
        #expect(auth.signingKeyId == "#active")
        #expect(auth.signedAt == 1_700_000_000_500)
    }

    @Test("ScpId.verify result has correct DID")
    func verifyResultHasCorrectDid() throws {
        let mockVerify: ScpId.VerifyFn = { _, _ in
            ScpIdTests.testAuthJson
        }

        let challenge = try ScpId.challenge(
            audience: "https://app.example.com",
            challengeFn: { _, _ in ScpIdTests.testChallengeJson }
        )
        let response = try ScpId.sign(
            identity: MockIdentity(did: "did:dht:z6MkTestSigner"),
            signingKeyId: "#active",
            challenge: challenge,
            signFn: { _, _, _ in ScpIdTests.testResponseJson }
        )

        let auth = try ScpId.verify(
            response: response,
            challenge: challenge,
            verifyFn: mockVerify
        )

        #expect(auth.did == "did:dht:z6MkTestSigner")
    }

    @Test("ScpId.verify propagates bridge errors for expired challenge")
    func verifyPropagatesErrors() throws {
        let mockVerify: ScpId.VerifyFn = { _, _ in
            throw ScpError.Identity(
                msg: "challenge has expired",
                code: "SCP-IDENT-1030"
            )
        }

        let challenge = try ScpId.challenge(
            audience: "https://app.example.com",
            challengeFn: { _, _ in ScpIdTests.testChallengeJson }
        )
        let response = try ScpId.sign(
            identity: MockIdentity(did: "did:dht:z6MkTestSigner"),
            signingKeyId: "#active",
            challenge: challenge,
            signFn: { _, _, _ in ScpIdTests.testResponseJson }
        )

        do {
            _ = try ScpId.verify(
                response: response,
                challenge: challenge,
                verifyFn: mockVerify
            )
            Issue.record("Expected ScpId.verify to throw")
        } catch let error as ScpError {
            if case let .Identity(message, code) = error {
                #expect(code == "SCP-IDENT-1030")
                #expect(message.contains("expired"))
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Challenge -> Sign -> Verify Roundtrip

    @Test("Full challenge -> sign -> verify roundtrip")
    func fullRoundtrip() throws {
        // This test verifies the full flow using mock bridge functions.
        // The mock bridge returns consistent JSON across all three steps.
        let challenge = try ScpId.challenge(
            audience: "https://app.example.com",
            ttl: 120,
            challengeFn: { _, _ in ScpIdTests.testChallengeJson }
        )

        let response = try ScpId.sign(
            identity: MockIdentity(did: "did:dht:z6MkTestSigner"),
            signingKeyId: "#active",
            challenge: challenge,
            signFn: { _, _, _ in ScpIdTests.testResponseJson }
        )

        let auth = try ScpId.verify(
            response: response,
            challenge: challenge,
            verifyFn: { _, _ in ScpIdTests.testAuthJson }
        )

        // Verify consistency across the roundtrip
        #expect(challenge.audience == "https://app.example.com")
        #expect(response.did == auth.did)
        #expect(response.signingKeyId == auth.signingKeyId)
        #expect(auth.did == "did:dht:z6MkTestSigner")
        #expect(auth.signingKeyId == "#active")
    }
}
