// Payload-opacity tests for adapter `ApplePushProvider`.
//
// Acceptance criterion 4 of ADR-025, the Apple platform adapter, in
// `.docs/adrs/phase-5.md` states what `handleNotification(payload:)` accepts:
// "The relay MUST send only `{"aps": {"content-available": 1}}` payloads. The
// adapter enforces opacity on receipt." The same criterion requires the adapter
// to throw "for a payload containing any field other than
// `aps.content-available`, for a `content-available` value other than the
// integer 1, and for bytes that are not a JSON object". §10.7, notifications
// and push, of `.docs/specs/10-infrastructure-and-self-hosting.md` is where
// that requirement comes from: a payload carrying a context ID, a sender
// identifier, or a message count would hand Apple metadata the protocol keeps
// encrypted.
//
// Each case below names the field it added, the value it changed, or the shape
// it broke, and requires the `PushError` case `handleNotification(payload:)`
// throws for that payload: `invalidPayload` for bytes that are not a JSON
// object, `opaquePayloadViolation` for every other rejection.
//
// `register()` reaches APNs through the shared application, and a `swift test`
// host holds no APNs entitlement and receives no device token. The callback
// cases therefore build the provider with a registration trigger that does
// nothing and deliver the AppDelegate callbacks themselves. Acceptance
// criterion 7 requires a test in which `register()` returns a token, and a
// `swift test` host cannot run that test.

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
        @Test("handleNotification returns the fixed wake signal for a silent push")
        func handleNotificationAcceptsOpaquePayload() async throws {
            let provider = ApplePushProvider()
            let bytes = try opaquePayload()

            let signal = try await provider.handleNotification(payload: bytes)
            #expect(signal == Data(#"{"aps":{"content-available":1}}"#.utf8))
        }

        @Test("handleNotification returns the fixed wake signal, not relay bytes that parse to it")
        func handleNotificationDiscardsAcceptedPayloadBytes() async throws {
            // Trailing whitespace is legal JSON, so these bytes parse to the one
            // payload §10.7 permits while carrying 100 bytes the relay chose.
            // Returning the received bytes would hand those bytes to the caller.
            let provider = ApplePushProvider()
            let bytes = try opaquePayload() + Data(String(repeating: " ", count: 100).utf8)

            let signal = try await provider.handleNotification(payload: bytes)
            #expect(signal != bytes)
            #expect(signal == Data(#"{"aps":{"content-available":1}}"#.utf8))
        }

        @Test("handleNotification accepts the permitted payload with whitespace between its tokens")
        func handleNotificationAcceptsWhitespaceBetweenTokens() async throws {
            // JSON whitespace may sit between any two tokens, so the byte
            // comparison must remove it before comparing.
            let provider = ApplePushProvider()
            let bytes = Data("{ \"aps\" :\t{\r\n  \"content-available\" : 1\n}\n}".utf8)

            let signal = try await provider.handleNotification(payload: bytes)
            #expect(signal == Data(#"{"aps":{"content-available":1}}"#.utf8))
        }

        @Test("handleNotification rejects a repeated aps key whose second value carries a context ID")
        func handleNotificationRejectsDuplicateApsCarryingContextId() async throws {
            // `JSONSerialization` keeps the first value for a key the object
            // repeats, so these bytes parse to the one payload §10.7 permits
            // while carrying a context ID in the second `aps` member.
            let provider = ApplePushProvider()
            let bytes = Data(#"{"aps":{"content-available":1},"aps":{"contextId":"ctx-42","content-available":1}}"#.utf8)
            let parsed = try JSONSerialization.jsonObject(with: bytes) as? [String: [String: Int]]
            #expect(parsed == ["aps": ["content-available": 1]])

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }

        @Test("handleNotification rejects a repeated content-available key")
        func handleNotificationRejectsDuplicateContentAvailable() async {
            let provider = ApplePushProvider()
            let bytes = Data(#"{"aps":{"content-available":1,"content-available":"ctx-42"}}"#.utf8)

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }

        @Test("handleNotification rejects a repeated aps key whose values match")
        func handleNotificationRejectsDuplicateApsKey() async {
            let provider = ApplePushProvider()
            let bytes = Data(#"{"aps":{"content-available":1},"aps":{"content-available":1}}"#.utf8)

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }

        @Test("handleNotification rejects an escaped key that decodes to aps")
        func handleNotificationRejectsEscapedKey() async throws {
            let provider = ApplePushProvider()
            let bytes = Data(#"{"\u0061ps":{"content-available":1}}"#.utf8)
            let parsed = try JSONSerialization.jsonObject(with: bytes) as? [String: [String: Int]]
            #expect(parsed == ["aps": ["content-available": 1]])

            await expectRejection(provider, bytes, .opaquePayloadViolation)
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
            // payload §10.7 permits and the call accepts them.
            let provider = ApplePushProvider()
            let bytes = try opaquePayload() + Data(String(repeating: " ", count: 5000).utf8)
            #expect(bytes.count > 4096)
            let parsed = try JSONSerialization.jsonObject(with: bytes) as? [String: [String: Int]]
            #expect(parsed == ["aps": ["content-available": 1]])

            await expectRejection(provider, bytes, .opaquePayloadViolation)
        }
    }

    /// Start `register()` on `provider` and return once the call is suspended
    /// on its continuation, or record an issue when it never suspends.
    private func startRegistration(
        _ provider: ApplePushProvider,
        sourceLocation: SourceLocation = #_sourceLocation
    ) async -> Task<Data, Error> {
        let registration = Task { try await provider.register() }
        var yields = 0
        while yields < 10000, await !provider.hasPendingRegistration {
            await Task.yield()
            yields += 1
        }
        #expect(await provider.hasPendingRegistration, "register() never suspended", sourceLocation: sourceLocation)
        return registration
    }

    /// Counts the calls `register()` makes to the registration trigger.
    @MainActor
    private final class RegistrationRequests {
        var count = 0
    }

    struct ApplePushRegistrationCallbackTests {
        @Test("register() asks the platform to start APNs registration once")
        func registerRequestsRemoteNotificationsOnce() async throws {
            let requests = await RegistrationRequests()
            let provider = ApplePushProvider(requestRemoteNotifications: { requests.count += 1 })
            let registration = await startRegistration(provider)

            var yields = 0
            while yields < 10000, await requests.count == 0 {
                await Task.yield()
                yields += 1
            }
            await provider.tokenDidRegister(Data([0x01, 0x02]))
            _ = try await registration.value

            #expect(await requests.count == 1)
        }

        // An AppDelegate forwards every APNs lifecycle event, including a second
        // token or a failure that arrives after one `register()` call already
        // resumed. Resuming a continuation twice traps the app, so each callback
        // clears the pending continuation before it resumes that continuation.
        // Each case below suspends a real `register()` call, delivers one
        // callback, and requires that no continuation stays pending; the second
        // callback then traps the test process when the first one left the
        // continuation set.

        @Test("tokenDidRegister resumes a suspended register() once and clears it")
        func tokenDidRegisterResumesPendingRegistrationOnce() async throws {
            let provider = ApplePushProvider(requestRemoteNotifications: {})
            let registration = await startRegistration(provider)

            await provider.tokenDidRegister(Data([0x01, 0x02]))
            #expect(await !provider.hasPendingRegistration)
            await provider.tokenDidRegister(Data([0x03, 0x04]))

            #expect(try await registration.value == Data([0x01, 0x02]))
        }

        @Test("registrationDidFail resumes a suspended register() once and clears it")
        func registrationDidFailResumesPendingRegistrationOnce() async {
            let provider = ApplePushProvider(requestRemoteNotifications: {})
            let registration = await startRegistration(provider)

            await provider.registrationDidFail(PushError.invalidPayload("first failure"))
            #expect(await !provider.hasPendingRegistration)
            await provider.registrationDidFail(PushError.invalidPayload("second failure"))

            do {
                _ = try await registration.value
                Issue.record("register() returned a token after registrationDidFail")
            } catch let PushError.registrationFailed(message) {
                #expect(message.contains("first failure"))
            } catch {
                Issue.record("caught \(error), which is not PushError.registrationFailed")
            }
        }
    }

#endif // os(iOS) || os(macOS)
