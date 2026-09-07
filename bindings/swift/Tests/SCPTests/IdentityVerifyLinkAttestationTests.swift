@testable import SCP
import XCTest

// Real-FFI call-through tests for `SCP.identityVerifyLinkAttestation`
// (spec §3.5.4).
//
// GitHub issue #2335 finding 2: §3.5.4 step 1 resolves an issuer's DID document
// and takes a signing key from it, so a key a caller supplies is an assertion to
// check rather than a source of truth. Checking it needs a per-instance DID
// resolver, and a module-scope UniFFI free function of the same name reaches no
// bridge instance and declines with `SCP-IDENT-1060`. These tests prove the
// Swift wrapper takes the per-instance route: an `SCP-IDENT-1060` here would
// mean it reverted to that free function.

final class IdentityVerifyLinkAttestationTests: XCTestCase {
    /// Builds a fresh instance per test. Each `SCP` owns its own bridge
    /// instance, so no test observes another's identity registry or storage.
    private func makeScp() throws -> SCP {
        try SCP(storage: .inMemory)
    }

    /// Malformed attestation JSON is a caller error the shared flow reports as
    /// `SCP-IDENT-1044`, before any resolution attempt. A wrapper routed to the
    /// declining free function reports `SCP-IDENT-1060` instead, whatever the
    /// arguments say.
    func testReachesThePerInstanceRoute() async throws {
        do {
            _ = try await makeScp().identityVerifyLinkAttestation(
                attestationJson: "not json",
                issuerPublicKeyHex: String(repeating: "00", count: 32),
                referenceProof: "not_fetched"
            )
            XCTFail("malformed attestation JSON must raise")
        } catch {
            let message = "\(error)"
            XCTAssertTrue(
                message.contains("SCP-IDENT-1044"),
                "malformed attestation JSON must report SCP-IDENT-1044, got: \(message)"
            )
            XCTAssertFalse(
                message.contains("SCP-IDENT-1060"),
                "SCP-IDENT-1060 means this wrapper reached a module-scope free function: \(message)"
            )
        }
    }

    /// `referenceProof` carries a caller's own class 2 fetch outcome (§3.5.4
    /// Class 2 step 2). One shared parser accepts `"confirmed"` and
    /// `"not_fetched"` and raises `SCP-IDENT-1044` for every other string, so a
    /// typo never lands a caller on a silent `"not_fetched"` verdict.
    func testRejectsAnUnknownReferenceProofValue() async throws {
        do {
            _ = try await makeScp().identityVerifyLinkAttestation(
                attestationJson: "not json",
                issuerPublicKeyHex: String(repeating: "00", count: 32),
                referenceProof: "Confirmed"
            )
            XCTFail("an unknown referenceProof must raise")
        } catch {
            XCTAssertTrue(
                "\(error)".contains("SCP-IDENT-1044"),
                "an unknown referenceProof must report SCP-IDENT-1044, got: \(error)"
            )
        }
    }
}
