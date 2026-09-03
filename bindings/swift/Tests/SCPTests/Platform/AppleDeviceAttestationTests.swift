// Fail-closed tests for the AppleDeviceAttestation adapter.
//
// `DCAppAttestService.isSupported` reads `false` on a simulator, on every Mac,
// and on any device where Apple does not provide App Attest. These tests pin
// what the adapter does on that path: `attest(challenge:deviceId:)` and
// `assertRequest(requestHash:)` each throw `AttestationError.unsupported` and
// return no bytes.
//
// The adapter previously returned `"software-attestation-<UUID>"` and
// `"software-assertion-<UUID>"` on that path, and declared a `verify(token:)`
// method that returned `true` for every non-empty token. Each of those three
// constructs reported success for work the adapter did not do, which the
// no-dev-stand-in tenet of `CLAUDE.md` forbids on a shipped path: "If the real
// backend isn't built, the capability **fails closed** (a typed error, or an
// honest protocol-supported absent state)."
//
// §9.3 of the security model spec governs what an unsupported device produces
// (`.docs/specs/09-security-model.md:187`): a device attestation is "an optional
// SDK-level trust signal, not a protocol-level uniqueness gate," and "Its
// absence is expected — desktop users, non-native clients, protocol-only
// implementations — and is not penalizing." §27.3.3 and §27.4.3 of the
// attestations spec record the F3 mint and verify surfaces this adapter sits in.

#if os(iOS) || os(macOS)

    import DeviceCheck
    import Foundation
    @testable import SCP
    import Testing

    // MARK: - Test double

    /// A `DCAppAttestService` that reports App Attest as unavailable.
    ///
    /// `DCAppAttestService` declares no unavailable initializer, so a subclass
    /// reaches `NSObject.init()` and overrides the one property the adapter reads
    /// before it calls the service.
    private final class UnsupportedAppAttestService: DCAppAttestService {
        override var isSupported: Bool {
            false
        }
    }

    // MARK: - AppleDeviceAttestation fail-closed tests

    struct AppleDeviceAttestationFailClosedTests {
        /// Builds an adapter over an unsupported service and a private
        /// `UserDefaults` suite, so no test writes the shared standard suite.
        private func makeAdapter() throws -> AppleDeviceAttestation {
            let suiteName = "dev.limn.scp.tests.\(UUID().uuidString)"
            let defaults = try #require(
                UserDefaults(suiteName: suiteName),
                "UserDefaults must open the private suite"
            )
            return AppleDeviceAttestation(
                service: UnsupportedAppAttestService(),
                defaults: defaults
            )
        }

        @Test("isHardwareBacked reports false when App Attest is unavailable")
        func hardwareBackedReportsFalse() throws {
            let adapter = try makeAdapter()
            #expect(adapter.isHardwareBacked == false)
        }

        @Test("attest throws unsupported instead of minting a synthetic token")
        func attestThrowsOnUnsupportedDevice() async throws {
            let adapter = try makeAdapter()
            await #expect(throws: AttestationError.self) {
                _ = try await adapter.attest(
                    challenge: Data([0x01, 0x02, 0x03, 0x04]),
                    deviceId: Data([0x05, 0x06, 0x07, 0x08])
                )
            }
        }

        @Test("attest names the unsupported case and returns no bytes")
        func attestErrorCaseIsUnsupported() async throws {
            let adapter = try makeAdapter()
            do {
                let token = try await adapter.attest(
                    challenge: Data([0x01]),
                    deviceId: Data([0x02])
                )
                Issue.record(
                    "attest returned \(token.count) bytes on an unsupported device"
                )
            } catch let error as AttestationError {
                guard case .unsupported = error else {
                    Issue.record("attest threw \(error) rather than .unsupported")
                    return
                }
            }
        }

        @Test("assertRequest throws unsupported instead of minting a synthetic assertion")
        func assertRequestThrowsOnUnsupportedDevice() async throws {
            let adapter = try makeAdapter()
            await #expect(throws: AttestationError.self) {
                _ = try await adapter.assertRequest(
                    requestHash: Data(repeating: 0xAB, count: 32)
                )
            }
        }

        @Test("assertRequest names the unsupported case and returns no bytes")
        func assertRequestErrorCaseIsUnsupported() async throws {
            let adapter = try makeAdapter()
            do {
                let assertion = try await adapter.assertRequest(
                    requestHash: Data(repeating: 0xAB, count: 32)
                )
                Issue.record(
                    "assertRequest returned \(assertion.count) bytes on an unsupported device"
                )
            } catch let error as AttestationError {
                guard case .unsupported = error else {
                    Issue.record("assertRequest threw \(error) rather than .unsupported")
                    return
                }
            }
        }

        @Test("assertRequest reaches the unsupported check before the stored-key check")
        func assertRequestFailsClosedWithNoStoredKey() async throws {
            // No `attest` call precedes this one, so no App Attest key ID is
            // stored. The adapter must report the missing platform service
            // rather than `keyNotFound`, because a caller that reads
            // `keyNotFound` would call `attest` and receive the same absence.
            let adapter = try makeAdapter()
            do {
                _ = try await adapter.assertRequest(
                    requestHash: Data(repeating: 0x11, count: 32)
                )
                Issue.record("assertRequest returned bytes on an unsupported device")
            } catch let error as AttestationError {
                guard case .unsupported = error else {
                    Issue.record("assertRequest threw \(error) rather than .unsupported")
                    return
                }
            }
        }
    }

#endif // os(iOS) || os(macOS)
