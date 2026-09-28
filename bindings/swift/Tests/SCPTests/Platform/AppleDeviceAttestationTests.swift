// Fail-closed tests for adapter `AppleDeviceAttestation`.
//
// These tests pin two properties of `AppleDeviceAttestation`:
//
// 1. When `DCAppAttestService.isSupported` is `false`, `attest` and
//    `assertRequest` throw `ScpError` code `SCP-ATTEST-9019`, the type the
//    UniFFI callback declares, and return no bytes.
//    §9.3 of SCP's security model spec, "Sybil resistance and identity
//    uniqueness", states that the absence of a device attestation is expected
//    and is not penalizing, so a typed error is an honest result and a
//    locally minted token would assert a hardware guarantee no hardware
//    produced.
// 2. `AttestationError.scpError` gives each `AttestationError` case its own
//    `SCP-ATTEST-` code, which `crates/scp-ffi/common/src/error_codes.rs`
//    registers.
//
// See ADR-025 (Apple Platform Adapter) in `.docs/adrs/phase-5.md` and the
// UniFFI `DeviceAttestationProvider` callback interface in
// `crates/scp-ffi/uniffi/src/lib.rs`, which the adapter conforms to.

#if os(iOS) || os(macOS)

    import CryptoKit
    import DeviceCheck
    import Foundation
    @testable import SCP
    import Testing

    // MARK: - Test doubles

    /// A `DCAppAttestService` that reports App Attest as unavailable, which is
    /// what a simulator reports, and what every device without a Secure
    /// Enclave App Attest key reports.
    private final class UnsupportedAppAttestService: DCAppAttestService, @unchecked Sendable {
        override var isSupported: Bool {
            false
        }
    }

    /// A `UserDefaults` that keeps every value in memory.
    ///
    /// `AppleDeviceAttestation` reads its key ID through `string(forKey:)` and
    /// writes it through `set(_:forKey:)`, so overriding those two methods
    /// covers every call it makes. A real `UserDefaults(suiteName:)` would
    /// leave one `~/Library/Preferences/<suiteName>.plist` behind per test,
    /// because `removePersistentDomain(forName:)` clears values and leaves that
    /// file, and because `cfprefsd` may write it after a test deleted it.
    /// Keeping values in memory writes nothing to delete.
    private final class InMemoryUserDefaults: UserDefaults, @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [String: String] = [:]

        override func string(forKey defaultName: String) -> String? {
            lock.withLock { storage[defaultName] }
        }

        override func set(_ value: Any?, forKey defaultName: String) {
            lock.withLock { storage[defaultName] = value as? String }
        }

        override func removeObject(forKey defaultName: String) {
            lock.withLock { storage[defaultName] = nil }
        }
    }

    // MARK: - Helpers

    /// An adapter under test, together with a defaults store it writes to.
    private struct AttestationHarness {
        let adapter: AppleDeviceAttestation
        let defaults: UserDefaults
    }

    /// Build an adapter whose App Attest service reports itself unavailable.
    private func makeUnsupportedAdapter() -> AttestationHarness {
        let defaults = InMemoryUserDefaults()
        let adapter = AppleDeviceAttestation(
            service: UnsupportedAppAttestService(),
            defaults: defaults
        )
        return AttestationHarness(adapter: adapter, defaults: defaults)
    }

    // MARK: - Fail-closed tests

    struct AppleDeviceAttestationFailClosedTests {
        /// Require `ScpError.Identity` carrying `SCP-ATTEST-9019`, the value the
        /// UniFFI `DeviceAttestationProvider` callback lowers into an error
        /// Rust receives.
        private func expectUnsupported(_ error: ScpError, from method: String) {
            guard case let .Identity(msg, code) = error else {
                Issue.record("\(method) threw \(error) instead of ScpError.Identity")
                return
            }
            #expect(code == "SCP-ATTEST-9019")
            #expect(msg.contains("isSupported"))
        }

        @Test("attest throws ScpError SCP-ATTEST-9019 when App Attest is unavailable")
        func attestThrowsUnsupported() async {
            let adapter = makeUnsupportedAdapter().adapter
            do throws(ScpError) {
                let token = try await adapter.attest(
                    challenge: Data(repeating: 0x01, count: 32),
                    deviceId: Data([0x04, 0x05, 0x06])
                )
                Issue.record("attest returned \(token.count) bytes on a device without App Attest")
            } catch {
                expectUnsupported(error, from: "attest")
            }
        }

        @Test("assertRequest throws ScpError SCP-ATTEST-9019 when App Attest is unavailable")
        func assertRequestThrowsUnsupported() async {
            let adapter = makeUnsupportedAdapter().adapter
            do throws(ScpError) {
                let assertion = try await adapter.assertRequest(requestHash: Data(repeating: 0xAB, count: 32))
                Issue.record("assertRequest returned \(assertion.count) bytes on a device without App Attest")
            } catch {
                expectUnsupported(error, from: "assertRequest")
            }
        }

        @Test("every AttestationError case maps to its own SCP-ATTEST code")
        func everyCaseHasItsOwnCode() {
            let cases: [AttestationError] = [
                .serviceError("m"), .unsupported("m"), .keyNotFound, .internalError("m")
            ]
            let codes = cases.compactMap { error -> String? in
                guard case let .Identity(_, code) = error.scpError else { return nil }
                return code
            }
            let expected = ["9001", "9019", "9020", "9025"]
            #expect(codes == expected.map { "SCP-ATTEST-\($0)" })
        }

        @Test("an attest on a device without App Attest stores no App Attest key ID")
        func unsupportedAttestStoresNoKeyId() async {
            let harness = makeUnsupportedAdapter()
            let adapter = harness.adapter

            _ = try? await adapter.attestReportingAttestationError(challenge: Data(repeating: 0x01, count: 32), deviceId: Data([0x02]))

            #expect(harness.defaults.string(forKey: "dev.limn.scp.appAttest.keyId") == nil)
        }

        @Test("isHardwareBacked reports false when App Attest is unavailable")
        func isHardwareBackedReportsFalse() {
            let harness = makeUnsupportedAdapter()
            let adapter = harness.adapter

            #expect(adapter.isHardwareBacked == false)
        }
    }

#endif // os(iOS) || os(macOS)
