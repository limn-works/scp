// Payload-opacity tests for adapter `ApplePushProvider`.
//
// Acceptance criterion 4 of ADR-025, the Apple platform adapter, in
// `.docs/adrs/phase-5.md` states what `handleNotification(payload:)` accepts:
// the relay sends only `{"aps": {"content-available": 1}}`, and "the adapter
// enforces opacity on receipt", rejecting "payloads containing any field other
// than `aps.content-available`". §10.7, notifications and push, of
// `.docs/specs/10-infrastructure-and-self-hosting.md` is where that requirement
// comes from: a payload carrying a context ID, a sender identifier, or
// a message count would hand Apple metadata the protocol keeps encrypted.
//
// Each case below names the field it added, the value it changed, or the shape
// it broke, and requires the `PushError` case `handleNotification(payload:)`
// throws for that payload: `invalidPayload` for bytes that are not a JSON
// object, `opaquePayloadViolation` for every other rejection.
//
// `register()` reaches APNs, and a `swift test` host holds no APNs entitlement
// and receives no device token, so no case here calls it. Acceptance criterion 7
// assigns `register()` to the physical-device lane.

#if os(iOS) || os(macOS)

    import Foundation
    @testable import SCP
    import Testing

    /// Encode `object` as the JSON bytes APNs would deliver.
    private func payload(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [])
    }

    /// The one payload §10.7 permits.
    private func opaquePayload() throws -> Data {
        try payload(["aps": ["content-available": 1]])
    }

    /// The `PushError` case a rejection test requires.
    private enum RejectionCase {
        case opaquePayloadViolation
        case invalidPayload
    }

    /// Call `handleNotification(payload:)` and record an issue unless it
    /// throws the `PushError` case `expected` names.
    private func expectRejection(
        _ provider: ApplePushProvider,
        _ bytes: Data,
        _ expected: RejectionCase,
        sourceLocation: SourceLocation = #_sourceLocation
    ) async {
        do {
            _ = try await provider.handleNotification(payload: bytes)
            Issue.record("handleNotification accepted a payload it must reject", sourceLocation: sourceLocation)
        } catch let error as PushError {
            switch (expected, error) {
            case (.opaquePayloadViolation, .opaquePayloadViolation), (.invalidPayload, .invalidPayload):
                break
            default:
                Issue.record("expected PushError.\(expected), caught \(error)", sourceLocation: sourceLocation)
            }
        } catch {
            Issue.record("caught \(error), which is not a PushError", sourceLocation: sourceLocation)
        }
    }

    struct ApplePushProviderPayloadTests {
        @Test("handleNotification returns the payload bytes for a silent push")
        func handleNotificationAcceptsOpaquePayload() async throws {
            let provider = ApplePushProvider()
            let bytes = try opaquePayload()

            let signal = try await provider.handleNotification(payload: bytes)
            #expect(signal == bytes)
        }

        @Test("handleNotification rejects a second top-level field")
        func handleNotificationRejectsExtraTopLevelField() async throws {
            let provider = ApplePushProvider()
            let bytes = try payload([
                "aps": ["content-available": 1],
                "contextId": "ctx-1"
            ])

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }

        @Test("handleNotification rejects a second field inside aps")
        func handleNotificationRejectsExtraApsField() async throws {
            let provider = ApplePushProvider()
            let bytes = try payload([
                "aps": ["content-available": 1, "badge": 3]
            ])

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }

        @Test("handleNotification rejects a payload whose only field is not aps")
        func handleNotificationRejectsNonApsField() async throws {
            let provider = ApplePushProvider()
            let bytes = try payload(["alert": ["content-available": 1]])

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }

        @Test("handleNotification rejects an aps value that is not an object")
        func handleNotificationRejectsNonObjectAps() async throws {
            let provider = ApplePushProvider()
            let bytes = try payload(["aps": 1])

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }

        @Test("handleNotification rejects content-available holding boolean true")
        func handleNotificationRejectsBooleanContentAvailable() async throws {
            // `JSONSerialization` bridges a JSON boolean and a JSON number to
            // one `NSNumber` class, and `NSNumber(value: true).intValue` reads
            // 1, so an implementation comparing `intValue` alone would accept
            // this payload.
            let provider = ApplePushProvider()
            let bytes = try payload(["aps": ["content-available": true]])

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }

        @Test("handleNotification rejects a content-available value other than 1")
        func handleNotificationRejectsWrongContentAvailableNumber() async throws {
            let provider = ApplePushProvider()
            let bytes = try payload(["aps": ["content-available": 0]])

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }

        @Test("handleNotification rejects a fractional content-available whose integer part is 1")
        func handleNotificationRejectsFractionalContentAvailable() async {
            // `NSNumber.intValue` truncates 1.5 to 1, so an implementation that
            // checks the CFNumber type and `intValue` alone would accept this
            // payload.
            let provider = ApplePushProvider()
            let bytes = Data(#"{"aps":{"content-available":1.5}}"#.utf8)

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }

        @Test("handleNotification rejects bytes that are not JSON")
        func handleNotificationRejectsNonJson() async {
            let provider = ApplePushProvider()

            await expectRejection(provider, Data([0xFF, 0x00, 0xFE]), .invalidPayload)
        }

        @Test("handleNotification rejects a JSON array")
        func handleNotificationRejectsJsonArray() async throws {
            let provider = ApplePushProvider()
            let bytes = try JSONSerialization.data(withJSONObject: [["aps": 1]], options: [])

            await expectRejection(provider, bytes, .invalidPayload)
        }

        @Test("handleNotification rejects a payload above the 4 KB APNs maximum")
        func handleNotificationRejectsOversizedPayload() async throws {
            // A payload this large reaches no device through APNs, and rejecting
            // it before `JSONSerialization` runs keeps a caller from spending
            // parse time on bytes APNs never sends.
            //
            // Trailing whitespace is legal JSON, so these bytes break no rule
            // but the size rule: without the size guard they parse as the one
            // payload §10.7 permits and the call returns them.
            let provider = ApplePushProvider()
            let bytes = try opaquePayload() + Data(String(repeating: " ", count: 5000).utf8)
            #expect(bytes.count > 4096)
            let parsed = try JSONSerialization.jsonObject(with: bytes) as? [String: [String: Int]]
            #expect(parsed == ["aps": ["content-available": 1]])

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }
    }

    struct ApplePushRegistrationCallbackTests {
        @Test("tokenDidRegister with no registration in flight changes nothing")
        func tokenDidRegisterWithoutPendingRegistration() async throws {
            // An AppDelegate forwards every APNs lifecycle event, including one
            // that arrives when no `register()` call is suspended. Resuming a
            // continuation twice traps, so this case pins that a token arriving
            // outside a registration resumes nothing, and that a later payload
            // still validates.
            let provider = ApplePushProvider()

            await provider.tokenDidRegister(Data([0x01, 0x02]))
            await provider.tokenDidRegister(Data([0x03, 0x04]))

            let bytes = try opaquePayload()
            let signal = try await provider.handleNotification(payload: bytes)
            #expect(signal == bytes)
        }

        @Test("registrationDidFail with no registration in flight changes nothing")
        func registrationDidFailWithoutPendingRegistration() async throws {
            let provider = ApplePushProvider()

            await provider.registrationDidFail(PushError.registrationFailed("no registration ran"))

            let bytes = try opaquePayload()
            let signal = try await provider.handleNotification(payload: bytes)
            #expect(signal == bytes)
        }
    }

#endif // os(iOS) || os(macOS)
