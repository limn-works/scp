// Fail-closed and rejection tests for the AppleDeviceAttestation adapter.
//
// These tests pin two properties of `AppleDeviceAttestation`:
//
// 1. When `DCAppAttestService.isSupported` is `false`, `attest` and
//    `assertRequest` throw `AttestationError.unsupported` and return no bytes.
//    §9.3 of the security model spec, "Sybil resistance and identity
//    uniqueness", states that a DID carrying no device attestation loses
//    nothing for the absence, so the typed error is the honest result and a
//    locally minted token would assert a hardware guarantee no hardware
//    produced.
// 2. `verify(token:)` rejects. Every case below that expects `false` names one
//    input class the structural criterion excludes.
//
// The adapter's criterion for `verify(token:)`: the bytes decode as one
// complete definite-length CBOR map carrying exactly `fmt`, `attStmt`, and
// `authData`, where `fmt` holds the text "apple-appattest", `attStmt` holds a
// map, and `authData` holds at least 37 bytes. Apple documents that shape in
// "Validating Apps That Connect to Your Server"; WebAuthn Level 2 §6.1 fixes
// the 37-byte floor as a 32-byte RP ID hash, one flags byte, and a 4-byte
// signature counter.
//
// See ADR-025 (Apple Platform Adapter) in `.docs/adrs/phase-5.md` and
// `crates/scp-platform/src/traits.rs` `DeviceAttestation`.

#if os(iOS) || os(macOS)

    import DeviceCheck
    import Foundation
    @testable import SCP
    import Testing

    // MARK: - Test doubles

    /// A `DCAppAttestService` that reports App Attest as unavailable, which is
    /// what the simulator and every device without a Secure Enclave App Attest
    /// key reports.
    private final class UnsupportedAppAttestService: DCAppAttestService, @unchecked Sendable {
        override var isSupported: Bool {
            false
        }
    }

    // MARK: - CBOR fixtures

    /// Builds the CBOR byte sequences the tests feed to `verify(token:)`.
    ///
    /// The encoder covers only the definite-length subset an App Attest
    /// attestation object uses, which is all the fixtures need.
    private enum CBORFixture {
        /// The `fmt` value Apple writes into a genuine attestation object.
        static let appleFormat = "apple-appattest"

        /// Encode one CBOR item head for `major` carrying `argument`.
        static func head(major: UInt8, argument: Int) -> [UInt8] {
            let prefix = major << 5
            if argument <= 23 {
                return [prefix | UInt8(argument)]
            }
            if argument <= 0xFF {
                return [prefix | 24, UInt8(argument)]
            }
            return [prefix | 25, UInt8((argument >> 8) & 0xFF), UInt8(argument & 0xFF)]
        }

        static func text(_ value: String) -> [UInt8] {
            let utf8 = [UInt8](value.utf8)
            return head(major: 3, argument: utf8.count) + utf8
        }

        static func byteString(_ value: [UInt8]) -> [UInt8] {
            head(major: 2, argument: value.count) + value
        }

        static func mapHeader(_ entryCount: Int) -> [UInt8] {
            head(major: 5, argument: entryCount)
        }

        static func arrayHeader(_ elementCount: Int) -> [UInt8] {
            head(major: 4, argument: elementCount)
        }

        /// The `attStmt` value Apple returns: a certificate chain plus a receipt.
        ///
        /// Nesting a map inside an array inside a map exercises the adapter's
        /// recursive skip path.
        static func attestationStatement() -> [UInt8] {
            var out = mapHeader(2)
            out += text("x5c")
            out += arrayHeader(2)
            out += byteString([UInt8](repeating: 0x30, count: 12))
            out += byteString([UInt8](repeating: 0x31, count: 9))
            out += text("receipt")
            out += byteString([UInt8](repeating: 0x0A, count: 6))
            return out
        }

        /// Assemble an attestation object, letting a caller vary one field so a
        /// test can name the single property it removed.
        static func attestationObject(
            format: String = appleFormat,
            authenticatorDataLength: Int = 37,
            extraKey: String? = nil
        ) -> Data {
            let entryCount = extraKey == nil ? 3 : 4
            var out = mapHeader(entryCount)
            out += text("fmt") + text(format)
            out += text("attStmt") + attestationStatement()
            out += text("authData")
                + byteString([UInt8](repeating: 0x11, count: authenticatorDataLength))
            if let extraKey {
                out += text(extraKey) + text("value")
            }
            return Data(out)
        }
    }

    // MARK: - Helpers

    /// An adapter under test, together with the `UserDefaults` suite it writes
    /// to, so each test can delete that suite when it finishes.
    private struct AttestationHarness {
        let adapter: AppleDeviceAttestation
        let defaults: UserDefaults
        let suiteName: String

        /// Remove the suite this harness created from the user defaults store.
        func removeSuite() {
            defaults.removePersistentDomain(forName: suiteName)
        }
    }

    /// Build an adapter whose App Attest service reports itself unavailable, and
    /// give it a `UserDefaults` suite no other test shares.
    private func makeUnsupportedAdapter() throws -> AttestationHarness {
        let suiteName = "dev.limn.scp.tests.attestation.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        let adapter = AppleDeviceAttestation(
            service: UnsupportedAppAttestService(),
            defaults: defaults
        )
        return AttestationHarness(adapter: adapter, defaults: defaults, suiteName: suiteName)
    }

    // MARK: - Fail-closed tests

    struct AppleDeviceAttestationFailClosedTests {
        @Test("attest throws AttestationError.unsupported when App Attest is unavailable")
        func attestThrowsUnsupported() async throws {
            let harness = try makeUnsupportedAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            do {
                let token = try await adapter.attest(
                    challenge: Data([0x01, 0x02, 0x03]),
                    deviceId: Data([0x04, 0x05, 0x06])
                )
                Issue.record(
                    "attest returned \(token.count) bytes on a device without App Attest instead of throwing"
                )
            } catch let error as AttestationError {
                guard case let .unsupported(reason) = error else {
                    Issue.record("attest threw \(error) instead of AttestationError.unsupported")
                    return
                }
                #expect(reason.contains("isSupported"))
            }
        }

        @Test("assertRequest throws AttestationError.unsupported when App Attest is unavailable")
        func assertRequestThrowsUnsupported() async throws {
            let harness = try makeUnsupportedAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            do {
                let assertion = try await adapter.assertRequest(
                    requestHash: Data(repeating: 0xAB, count: 32)
                )
                Issue.record(
                    "assertRequest returned \(assertion.count) bytes on a device without App Attest instead of throwing"
                )
            } catch let error as AttestationError {
                guard case let .unsupported(reason) = error else {
                    Issue.record(
                        "assertRequest threw \(error) instead of AttestationError.unsupported"
                    )
                    return
                }
                #expect(reason.contains("isSupported"))
            }
        }

        @Test("a failed attest stores no App Attest key ID")
        func failedAttestStoresNoKeyId() async throws {
            let harness = try makeUnsupportedAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            _ = try? await adapter.attest(challenge: Data([0x01]), deviceId: Data([0x02]))

            #expect(harness.defaults.string(forKey: "dev.limn.scp.appAttest.keyId") == nil)
        }

        @Test("isHardwareBacked reports false when App Attest is unavailable")
        func isHardwareBackedReportsFalse() throws {
            let harness = try makeUnsupportedAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            #expect(adapter.isHardwareBacked == false)
        }
    }

    // MARK: - verify(token:) rejection tests

    struct AppleDeviceAttestationVerifyTests {
        /// Every `verify` case needs an adapter instance; the service double
        /// never runs, because `verify` consults no service.
        private func makeAdapter() throws -> AttestationHarness {
            try makeUnsupportedAdapter()
        }

        @Test("verify accepts a structurally complete App Attest attestation object")
        func verifyAcceptsWellFormedObject() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            #expect(adapter.verify(token: CBORFixture.attestationObject()) == true)
        }

        @Test("verify rejects an empty token")
        func verifyRejectsEmpty() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            #expect(adapter.verify(token: Data()) == false)
        }

        @Test("verify rejects the synthetic software token this adapter once minted")
        func verifyRejectsSyntheticSoftwareToken() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            // Before the fail-closed change, `attest` minted this exact shape on
            // an unsupported device and `verify` returned true for it.
            let legacyToken = Data("software-attestation-\(UUID().uuidString)".utf8)
            #expect(adapter.verify(token: legacyToken) == false)
        }

        @Test("verify rejects arbitrary non-CBOR bytes")
        func verifyRejectsArbitraryBytes() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            #expect(adapter.verify(token: Data(repeating: 0xFF, count: 256)) == false)
            #expect(adapter.verify(token: Data("not an attestation".utf8)) == false)
        }

        @Test("verify rejects an attestation object whose fmt is not apple-appattest")
        func verifyRejectsForeignFormat() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(format: "packed")
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects authenticator data shorter than 37 bytes")
        func verifyRejectsShortAuthenticatorData() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(authenticatorDataLength: 36)
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an attestation object carrying an unknown key")
        func verifyRejectsUnknownKey() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            let token = CBORFixture.attestationObject(extraKey: "smuggled")
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects a truncated attestation object")
        func verifyRejectsTruncatedObject() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            let complete = CBORFixture.attestationObject()
            let truncated = complete.prefix(complete.count - 5)
            #expect(adapter.verify(token: Data(truncated)) == false)
        }

        @Test("verify rejects an attestation object followed by trailing bytes")
        func verifyRejectsTrailingBytes() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            var token = CBORFixture.attestationObject()
            token.append(contentsOf: [0x00, 0x01])
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects a top-level item that is not a map")
        func verifyRejectsNonMapTopLevel() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            let arrayToken = Data(CBORFixture.arrayHeader(0))
            #expect(adapter.verify(token: arrayToken) == false)
        }

        @Test("verify rejects an indefinite-length map")
        func verifyRejectsIndefiniteLengthMap() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            // 0xBF opens an indefinite-length map; 0xFF closes it. Apple emits
            // definite lengths only, so the adapter rejects this encoding.
            var out: [UInt8] = [0xBF]
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += [0xFF]
            #expect(adapter.verify(token: Data(out)) == false)
        }

        @Test("verify rejects a map that declares more entries than its bytes hold")
        func verifyRejectsOverlongMapCount() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            // A map header claiming 65535 entries followed by two bytes.
            let token = Data(CBORFixture.head(major: 5, argument: 0xFFFF) + [0x61, 0x66])
            #expect(adapter.verify(token: token) == false)
        }

        @Test("verify rejects an attestation object missing a required key")
        func verifyRejectsMissingKey() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            var out = CBORFixture.mapHeader(2)
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += CBORFixture.text("attStmt") + CBORFixture.attestationStatement()
            #expect(adapter.verify(token: Data(out)) == false)
        }

        @Test("verify rejects an attestation object that repeats a key")
        func verifyRejectsDuplicateKey() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            var out = CBORFixture.mapHeader(4)
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += CBORFixture.text("attStmt") + CBORFixture.attestationStatement()
            out += CBORFixture.text("authData")
                + CBORFixture.byteString([UInt8](repeating: 0x11, count: 37))
            #expect(adapter.verify(token: Data(out)) == false)
        }

        @Test("verify rejects an attestation object whose attStmt is not a map")
        func verifyRejectsNonMapAttestationStatement() throws {
            let harness = try makeAdapter()
            defer { harness.removeSuite() }
            let adapter = harness.adapter

            var out = CBORFixture.mapHeader(3)
            out += CBORFixture.text("fmt") + CBORFixture.text(CBORFixture.appleFormat)
            out += CBORFixture.text("attStmt") + CBORFixture.byteString([0x01, 0x02])
            out += CBORFixture.text("authData")
                + CBORFixture.byteString([UInt8](repeating: 0x11, count: 37))
            #expect(adapter.verify(token: Data(out)) == false)
        }
    }

#endif // os(iOS) || os(macOS)
