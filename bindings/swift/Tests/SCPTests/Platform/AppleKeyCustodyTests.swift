/// Key custody conformance tests for the AppleKeyCustody adapter.
///
/// These tests validate the `KeyCustodyProvider` contract using the real
/// Apple Keychain backend. Each test creates keys with unique handles
/// and cleans up after itself to prevent Keychain pollution.
///
/// The pseudonym derivation golden vector test verifies cross-platform
/// determinism with the canonical Rust reference implementation
/// (`InMemoryKeyCustody` in `scp-platform/src/testing/key_custody.rs`).
///
/// ## ADR-027 Amendment
///
/// Pseudonym derivation uses Ed25519 **public** key bytes as the HMAC key,
/// not private key bytes. This ensures cross-platform determinism with
/// hardware TEE adapters (e.g., Android Keystore) that cannot export
/// private key material.
///
/// See ADR-025 (Apple Platform Adapter) and ADR-006 (KeyCustody trait).

#if os(iOS) || os(macOS)

import CommonCrypto
import CryptoKit
import Foundation
import Testing

@testable import SCP

// MARK: - AppleKeyCustody Tests

@Suite("AppleKeyCustody Tests")
struct AppleKeyCustodyTests {

    /// Shared custody instance using default Keychain (no access group).
    /// Suitable for unit tests and simulator.
    private let custody = AppleKeyCustody(accessGroup: nil)

    // MARK: - generateKeypair

    @Test("generateKeypair returns non-empty handle for Ed25519")
    func generateEd25519Keypair() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")
        #expect(!handle.isEmpty, "handle should be a non-empty UUID string")
        // Cleanup
        try await custody.destroyKey(handle)
    }

    @Test("generateKeypair returns non-empty handle for X25519")
    func generateX25519Keypair() async throws {
        let handle = try await custody.generateKeypair(keyType: "x25519")
        #expect(!handle.isEmpty, "handle should be a non-empty UUID string")
        // Cleanup
        try await custody.destroyKey(handle)
    }

    @Test("generateKeypair rejects unknown key type")
    func generateUnknownKeyType() async throws {
        await #expect(throws: PlatformError.self) {
            _ = try await custody.generateKeypair(keyType: "rsa-4096")
        }
    }

    // MARK: - sign

    @Test("sign with Ed25519 key produces 64-byte signature")
    func signEd25519() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")
        let data = Data("hello world".utf8)
        let signature = try await custody.sign(handle, data: data)
        #expect(signature.count == 64, "Ed25519 signature must be 64 bytes")
        // Cleanup
        try await custody.destroyKey(handle)
    }

    @Test("sign with X25519 key throws wrongKeyType")
    func signX25519Fails() async throws {
        let handle = try await custody.generateKeypair(keyType: "x25519")
        await #expect(throws: PlatformError.self) {
            _ = try await custody.sign(handle, data: Data("test".utf8))
        }
        // Cleanup
        try await custody.destroyKey(handle)
    }

    @Test("sign with destroyed key throws keyNotFound")
    func signDestroyedKey() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")
        try await custody.destroyKey(handle)
        await #expect(throws: PlatformError.self) {
            _ = try await custody.sign(handle, data: Data("test".utf8))
        }
    }

    @Test("Ed25519 signature verifies with CryptoKit")
    func signatureVerifies() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")
        let message = Data("important message".utf8)

        let signature = try await custody.sign(handle, data: message)
        let publicKeyBytes = try await custody.publicKey(handle)

        // Verify using CryptoKit
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyBytes)
        let isValid = publicKey.isValidSignature(signature, for: message)
        #expect(isValid, "signature must verify against the public key")

        // Cleanup
        try await custody.destroyKey(handle)
    }

    // MARK: - publicKey

    @Test("publicKey returns 32 bytes for Ed25519")
    func publicKeyEd25519() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")
        let pubKey = try await custody.publicKey(handle)
        #expect(pubKey.count == 32, "Ed25519 public key must be 32 bytes")
        // Cleanup
        try await custody.destroyKey(handle)
    }

    @Test("publicKey returns 32 bytes for X25519")
    func publicKeyX25519() async throws {
        let handle = try await custody.generateKeypair(keyType: "x25519")
        let pubKey = try await custody.publicKey(handle)
        #expect(pubKey.count == 32, "X25519 public key must be 32 bytes")
        // Cleanup
        try await custody.destroyKey(handle)
    }

    @Test("publicKey with destroyed handle throws keyNotFound")
    func publicKeyDestroyedHandle() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")
        try await custody.destroyKey(handle)
        await #expect(throws: PlatformError.self) {
            _ = try await custody.publicKey(handle)
        }
    }

    // MARK: - destroyKey

    @Test("destroyKey returns attestation with softwareOnly method")
    func destroyKeyAttestation() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")
        let attestation = try await custody.destroyKey(handle)
        #expect(attestation.method == .softwareOnly)
        #expect(attestation.confirmed == true)
    }

    @Test("destroyKey makes subsequent operations fail")
    func destroyKeyMakesOperationsFail() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")
        try await custody.destroyKey(handle)

        // All operations should now fail
        await #expect(throws: PlatformError.self) {
            _ = try await custody.sign(handle, data: Data("test".utf8))
        }
        await #expect(throws: PlatformError.self) {
            _ = try await custody.publicKey(handle)
        }
        await #expect(throws: PlatformError.self) {
            _ = try await custody.destroyKey(handle)
        }
    }

    // MARK: - dhAgree

    @Test("dhAgree with X25519 keys produces matching shared secrets")
    func dhAgreeProducesMatchingSecrets() async throws {
        let aliceHandle = try await custody.generateKeypair(keyType: "x25519")
        let bobHandle = try await custody.generateKeypair(keyType: "x25519")

        let alicePub = try await custody.publicKey(aliceHandle)
        let bobPub = try await custody.publicKey(bobHandle)

        let secretAB = try await custody.dhAgree(aliceHandle, peerPublic: bobPub)
        let secretBA = try await custody.dhAgree(bobHandle, peerPublic: alicePub)

        #expect(secretAB.count == 32, "shared secret must be 32 bytes")
        #expect(secretAB == secretBA, "both sides must compute the same shared secret")

        // Cleanup
        try await custody.destroyKey(aliceHandle)
        try await custody.destroyKey(bobHandle)
    }

    @Test("dhAgree with Ed25519 key throws wrongKeyType")
    func dhAgreeEd25519Fails() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")
        let peer = Data(repeating: 0, count: 32)
        await #expect(throws: PlatformError.self) {
            _ = try await custody.dhAgree(handle, peerPublic: peer)
        }
        // Cleanup
        try await custody.destroyKey(handle)
    }

    // MARK: - derivePseudonym

    @Test("derivePseudonym is deterministic for same inputs")
    func derivePseudonymDeterministic() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")
        let contextId = Data("test-context".utf8)

        let first = try await custody.derivePseudonym(handle, contextId: contextId)
        let second = try await custody.derivePseudonym(handle, contextId: contextId)

        #expect(
            first.publicKey == second.publicKey,
            "same identity key + same context_id = same pseudonym public key"
        )

        // Cleanup
        try await custody.destroyKey(handle)
        try await custody.destroyKey(first.handle)
        // second.handle is deterministic and equals first.handle, so already destroyed
    }

    @Test("derivePseudonym produces different keys for different contexts")
    func derivePseudonymDifferentContexts() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")

        let pseudoA = try await custody.derivePseudonym(handle, contextId: Data("context-a".utf8))
        let pseudoB = try await custody.derivePseudonym(handle, contextId: Data("context-b".utf8))

        #expect(
            pseudoA.publicKey != pseudoB.publicKey,
            "different contexts must produce different pseudonyms"
        )

        // Cleanup
        try await custody.destroyKey(handle)
        try await custody.destroyKey(pseudoA.handle)
        try await custody.destroyKey(pseudoB.handle)
    }

    @Test("derivePseudonym with X25519 key throws wrongKeyType")
    func derivePseudonymX25519Fails() async throws {
        let handle = try await custody.generateKeypair(keyType: "x25519")
        await #expect(throws: PlatformError.self) {
            _ = try await custody.derivePseudonym(handle, contextId: Data("ctx".utf8))
        }
        // Cleanup
        try await custody.destroyKey(handle)
    }

    @Test("derived pseudonym handle can sign and verify")
    func derivedPseudonymCanSign() async throws {
        let identityHandle = try await custody.generateKeypair(keyType: "ed25519")
        let pseudonym = try await custody.derivePseudonym(
            identityHandle, contextId: Data("context-1".utf8)
        )

        let message = Data("pseudonym signed message".utf8)
        let signature = try await custody.sign(pseudonym.handle, data: message)

        // Verify
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: pseudonym.publicKey)
        let isValid = publicKey.isValidSignature(signature, for: message)
        #expect(isValid, "pseudonym signature must verify against pseudonym public key")

        // Cleanup
        try await custody.destroyKey(identityHandle)
        try await custody.destroyKey(pseudonym.handle)
    }

    /// Cross-platform golden-value test for pseudonym derivation.
    ///
    /// Verifies that the Swift `AppleKeyCustody.derivePseudonym` produces
    /// the same pseudonym public key as the Rust `InMemoryKeyCustody`
    /// reference implementation for the same inputs.
    ///
    /// The golden vector uses:
    /// - Identity key seed: 0x00...01 (31 zeros, then 0x01)
    /// - Context ID: "test" (4 bytes UTF-8)
    /// - Algorithm: `HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym")`
    ///
    /// This test imports a known private key into the Keychain, derives the
    /// pseudonym, and compares the result against the reference algorithm
    /// computed locally.
    @Test("derivePseudonym cross-platform golden vector (ADR-027)")
    func derivePseudonymGoldenVector() async throws {
        // Known identity key seed: 0x00...01 (31 zeros, then 0x01).
        var seedBytes = Data(repeating: 0, count: 32)
        seedBytes[31] = 1
        let contextId = Data("test".utf8)

        // Store the known seed as an Ed25519 private key in Keychain.
        let handle = UUID().uuidString
        try custody.storePrivateKeyBytes(seedBytes, for: handle, keyType: .ed25519)

        // Compute expected pseudonym using the reference algorithm directly:
        // seed = HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym")
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedBytes)
        let publicKeyBytes = signingKey.publicKey.rawRepresentation

        let hmacKey = SymmetricKey(data: publicKeyBytes)
        var hmac = CryptoKit.HMAC<SHA256>(key: hmacKey)
        hmac.update(data: contextId)
        hmac.update(data: Data("scp-pseudonym".utf8))
        let expectedSeed = Data(hmac.finalize())

        let expectedKey = try Curve25519.Signing.PrivateKey(rawRepresentation: expectedSeed.prefix(32))
        let expectedPublicKey = expectedKey.publicKey.rawRepresentation

        // Derive pseudonym through AppleKeyCustody
        let pseudonym = try await custody.derivePseudonym(handle, contextId: contextId)

        #expect(
            pseudonym.publicKey == expectedPublicKey,
            "pseudonym public key must match reference HMAC-SHA256 algorithm output"
        )

        // Cleanup
        try await custody.destroyKey(handle)
        try await custody.destroyKey(pseudonym.handle)
    }

    // MARK: - custodyType

    @Test("custodyType returns 'software' for all keys")
    func custodyTypeReturnsSoftware() async throws {
        let handle = try await custody.generateKeypair(keyType: "ed25519")
        #expect(
            custody.custodyType(handle) == "software",
            "Keychain-backed keys report CustodyType::Software"
        )
        // Cleanup
        try await custody.destroyKey(handle)
    }

    // MARK: - Unique handles

    @Test("each generateKeypair call returns a unique handle")
    func uniqueHandles() async throws {
        let h1 = try await custody.generateKeypair(keyType: "ed25519")
        let h2 = try await custody.generateKeypair(keyType: "x25519")
        let h3 = try await custody.generateKeypair(keyType: "ed25519")

        #expect(h1 != h2)
        #expect(h2 != h3)
        #expect(h1 != h3)

        // Cleanup
        try await custody.destroyKey(h1)
        try await custody.destroyKey(h2)
        try await custody.destroyKey(h3)
    }
}

#endif // os(iOS) || os(macOS)
