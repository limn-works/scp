// ApplePushProvider — APNs push notification registration with opaque silent-push payloads.
//
// This file implements the ``PushProvider`` callback interface (defined in
// `crates/scp-ffi/uniffi/src/lib.rs`) for Apple platforms (iOS 17+, macOS 14+).
//
// ## Architecture
//
// `ApplePushProvider` is a Swift actor that bridges the asynchronous APNs token
// delivery lifecycle into the synchronous UniFFI callback interface. It is one of
// the four platform providers assembled by ``ApplePlatformAdapter`` (ADR-025) and
// injected into the Rust engine at SDK initialisation.
//
// ## APNs Payload Opacity (§10.7)
//
// The relay sends **only** `{"aps": {"content-available": 1}}` — a silent push.
// No context ID, sender DID, message preview, or any other metadata may appear
// in the payload. Silent push wakes the app in the background; the SCP engine
// then connects to its relay set and pulls all pending encrypted envelopes.
// Apple learns only that the device received a notification at a specific time.
//
// `handleNotification(payload:)` **enforces** this invariant on receipt: payloads
// containing any field other than `aps.content-available` are rejected with
// ``PushError/opaquePayloadViolation``.
//
// ## Token Registration Lifecycle
//
// APNs token registration is asynchronous and callback-driven via AppDelegate:
// 1. `register()` calls `registerForRemoteNotifications()` and suspends via a
//    `CheckedContinuation`.
// 2. The AppDelegate calls `tokenDidRegister(_:)` when the token arrives, or
//    `registrationDidFail(_:)` on error.
// 3. The continuation resumes and `register()` returns the raw device token bytes.
//
// The `ApplePushProvider` instance must be stored by the app and the AppDelegate
// must forward APNs lifecycle events to it.
//
// ## Thread Safety
//
// `ApplePushProvider` is a Swift actor. UniFFI callback interfaces execute on Rust
// tokio threads — not the Swift or macOS main thread. The actor executor serialises
// all state mutations without data races.
//
// See ADR-025 (Apple Platform Adapter), ADR-021 (UniFFI Bridge), and §10.7.

#if os(iOS) || os(macOS)

    import Foundation

    #if canImport(UIKit)
        import UIKit
    #elseif canImport(AppKit)
        import AppKit
    #endif

    // MARK: - PushError

    /// Errors produced by ``ApplePushProvider`` operations.
    public enum PushError: Error, Sendable {
        /// APNs registration failed. Carries the underlying platform error description.
        case registrationFailed(String)
        /// A concurrent `register()` call is already in flight.
        case registrationAlreadyInProgress
        /// The received push payload violates the §10.7 opacity requirement.
        ///
        /// The relay MUST send only `{"aps": {"content-available": 1}}`. Any deviation
        /// from this format is rejected to prevent metadata leakage.
        case opaquePayloadViolation(String)
        /// The notification payload could not be deserialised as JSON.
        case invalidPayload(String)
    }

    extension PushError: LocalizedError {
        public var errorDescription: String? {
            switch self {
            case let .registrationFailed(message):
                return "APNs registration failed: \(message)"
            case .registrationAlreadyInProgress:
                return "APNs registration is already in progress"
            case let .opaquePayloadViolation(detail):
                return "Push payload violates §10.7 opacity requirement: \(detail)"
            case let .invalidPayload(detail):
                return "Push payload is not valid JSON: \(detail)"
            }
        }
    }

    // MARK: - ApplePushProvider

    /// Actor-isolated APNs push notification provider for the SCP Rust engine.
    ///
    /// Conforms to the UniFFI-generated `PushProvider` protocol so that it can be
    /// injected into the engine via the callback interface bridge (ADR-021).
    ///
    /// ## AppDelegate Integration
    ///
    /// The host application's AppDelegate must call the following methods on the
    /// stored `ApplePushProvider` instance:
    ///
    /// ```swift
    /// // In AppDelegate.application(_:didRegisterForRemoteNotificationsWithDeviceToken:)
    /// pushProvider.tokenDidRegister(deviceToken)
    ///
    /// // In AppDelegate.application(_:didFailToRegisterForRemoteNotificationsWithError:)
    /// pushProvider.registrationDidFail(error)
    /// ```
    ///
    /// Usage:
    /// ```swift
    /// let pushProvider = ApplePushProvider()
    /// // Pass to SCP engine via ApplePlatformAdapter
    /// ```
    public actor ApplePushProvider {
        // MARK: Internal state

        /// Pending continuation waiting for the APNs device token or registration error.
        ///
        /// Set by ``register()`` and consumed (exactly once) by ``tokenDidRegister(_:)``
        /// or ``registrationDidFail(_:)``. After consumption it is set back to `nil`.
        private var tokenContinuation: CheckedContinuation<Data, Error>?

        // MARK: Initialiser

        /// Creates a new `ApplePushProvider`.
        ///
        /// Typically called once by ``ApplePlatformAdapter/make()``.
        public init() {}

        // MARK: PushProvider implementation

        /// Register for APNs push notifications and return the device token bytes.
        ///
        /// Calls the platform-specific `registerForRemoteNotifications()` method and
        /// suspends until the AppDelegate delivers the token (or an error) via
        /// ``tokenDidRegister(_:)`` / ``registrationDidFail(_:)``. Races a 30-second
        /// timeout so callers are never blocked indefinitely.
        ///
        /// - Returns: The raw APNs device token bytes (typically 32 bytes). The caller
        ///   (the SCP Rust engine via UniFFI) converts these bytes to the hex string
        ///   that is forwarded to the relay as a `PushToken`.
        ///
        /// - Throws:
        ///   - ``PushError/registrationAlreadyInProgress`` if a concurrent call is
        ///     already awaiting a token.
        ///   - ``PushError/registrationFailed(_:)`` if the platform rejects registration
        ///     or the 30-second timeout elapses.
        public func register() async throws -> Data {
            guard tokenContinuation == nil else {
                throw PushError.registrationAlreadyInProgress
            }

            // Trigger registration on the main thread before suspending.
            Task { @MainActor in
                #if canImport(UIKit)
                    UIApplication.shared.registerForRemoteNotifications()
                #elseif canImport(AppKit)
                    NSApplication.shared.registerForRemoteNotifications()
                #endif
            }

            // Start a 30-second timeout that calls back into the actor on expiry.
            // Using `[weak self]` avoids a retain cycle; actor hop via `await` is
            // implicit when calling `self?._timeoutRegistration()`.
            let timeoutTask = Task { [weak self] in
                try await Task.sleep(nanoseconds: 30_000_000_000)
                await self?._timeoutRegistration()
            }

            do {
                // `withCheckedThrowingContinuation` closure runs synchronously on
                // the actor's executor — assigning `tokenContinuation` here is safe.
                let result = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                    self.tokenContinuation = continuation
                }
                timeoutTask.cancel()
                return result
            } catch {
                timeoutTask.cancel()
                throw error
            }
        }

        /// Called by the timeout `Task` when the 30-second window elapses.
        ///
        /// Runs on the actor's executor (via `await`). Resumes the pending
        /// continuation with a timeout error; no-ops if the token already arrived.
        private func _timeoutRegistration() {
            guard let cont = tokenContinuation else { return }
            tokenContinuation = nil
            cont.resume(throwing: PushError.registrationFailed(
                "APNs registration timed out after 30 s — ensure push entitlements are configured"
            ))
        }

        /// Handle an incoming APNs silent push notification.
        ///
        /// Validates that `payload` is the strictly opaque `{"aps": {"content-available": 1}}`
        /// format required by §10.7. Any additional field in the payload — at the top level
        /// or nested inside `aps` — is rejected with ``PushError/opaquePayloadViolation``.
        ///
        /// When the payload is valid, the method returns the raw payload bytes as the wake
        /// signal. The SCP engine uses the wake signal to trigger a relay pull for pending
        /// encrypted envelopes. No context ID, sender DID, or message count is extracted
        /// from the payload — there is nothing to extract.
        ///
        /// - Parameter payload: The raw JSON bytes delivered by APNs.
        /// - Returns: The raw `payload` bytes as the wake signal, passed opaquely to the
        ///   SCP engine.
        ///
        /// - Throws:
        ///   - ``PushError/invalidPayload(_:)`` if the bytes cannot be parsed as JSON or the
        ///     top-level structure is not a dictionary.
        ///   - ``PushError/opaquePayloadViolation(_:)`` if the payload contains any field
        ///     other than `aps.content-available`.
        public func handleNotification(payload: Data) throws -> Data {
            try validateOpaquePayload(payload)
            // The payload bytes are returned as the wake signal. The content is opaque —
            // the engine fetches pending envelopes from the relay upon receipt.
            return payload
        }

        // MARK: AppDelegate callbacks

        /// Called by the AppDelegate when APNs delivers the device token.
        ///
        /// Resumes the continuation that was suspended in ``register()``. Safe to call
        /// from any thread — the actor serialises the state mutation.
        ///
        /// ```swift
        /// // AppDelegate.application(_:didRegisterForRemoteNotificationsWithDeviceToken:)
        /// func application(
        ///     _ application: UIApplication,
        ///     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
        /// ) {
        ///     pushProvider.tokenDidRegister(deviceToken)
        /// }
        /// ```
        ///
        /// - Parameter token: The raw APNs device token bytes provided by the system.
        public func tokenDidRegister(_ token: Data) {
            guard let cont = tokenContinuation else { return }
            tokenContinuation = nil
            cont.resume(returning: token)
        }

        /// Called by the AppDelegate when APNs registration fails.
        ///
        /// Resumes the continuation that was suspended in ``register()`` with an error.
        /// Safe to call from any thread — the actor serialises the state mutation.
        ///
        /// ```swift
        /// // AppDelegate.application(_:didFailToRegisterForRemoteNotificationsWithError:)
        /// func application(
        ///     _ application: UIApplication,
        ///     didFailToRegisterForRemoteNotificationsWithError error: Error
        /// ) {
        ///     pushProvider.registrationDidFail(error)
        /// }
        /// ```
        ///
        /// - Parameter error: The error returned by the platform.
        public func registrationDidFail(_ error: Error) {
            guard let cont = tokenContinuation else { return }
            tokenContinuation = nil
            cont.resume(throwing: PushError.registrationFailed(error.localizedDescription))
        }

        // MARK: Payload validation

        /// Validate that `payload` satisfies the §10.7 opacity requirement.
        ///
        /// The valid payload has **exactly** this structure and no other fields:
        /// ```json
        /// {"aps": {"content-available": 1}}
        /// ```
        ///
        /// Validation rules (all must pass):
        /// 1. The payload parses as a JSON object.
        /// 2. The top-level object has **exactly one** key: `"aps"`.
        /// 3. The `aps` value is a JSON object with **exactly one** key:
        ///    `"content-available"`.
        /// 4. The `content-available` value is the integer `1`.
        ///
        /// - Parameter payload: Raw JSON bytes to validate.
        /// - Throws: ``PushError/invalidPayload(_:)`` or ``PushError/opaquePayloadViolation(_:)``.
        private func validateOpaquePayload(_ payload: Data) throws {
            // APNs payload limit is 4 KB for standard push; reject oversized payloads early.
            let maxPayloadBytes = 4096
            guard payload.count <= maxPayloadBytes else {
                throw PushError.opaquePayloadViolation(
                    "payload size \(payload.count) bytes exceeds 4 KB APNs maximum"
                )
            }

            // Deserialise JSON.
            let json: Any
            do {
                json = try JSONSerialization.jsonObject(with: payload, options: [])
            } catch {
                throw PushError.invalidPayload(error.localizedDescription)
            }

            guard let topLevel = json as? [String: Any] else {
                throw PushError.invalidPayload("payload root is not a JSON object")
            }

            // Rule 2: exactly one top-level key — "aps".
            guard topLevel.count == 1, let aps = topLevel["aps"] else {
                let keys = topLevel.keys.sorted().joined(separator: ", ")
                throw PushError.opaquePayloadViolation(
                    "top-level object must contain only \"aps\" but found: [\(keys)]"
                )
            }

            guard let apsDict = aps as? [String: Any] else {
                throw PushError.opaquePayloadViolation("\"aps\" value is not a JSON object")
            }

            // Rule 3: exactly one key inside "aps" — "content-available".
            guard apsDict.count == 1, let contentAvailable = apsDict["content-available"] else {
                let keys = apsDict.keys.sorted().joined(separator: ", ")
                throw PushError.opaquePayloadViolation(
                    "\"aps\" object must contain only \"content-available\" but found: [\(keys)]"
                )
            }

            // Rule 4: content-available must be the integer 1 (not boolean true).
            // JSONSerialization bridges both JSON numbers and JSON booleans to NSNumber.
            // __NSCFBoolean is a NSNumber subclass; NSNumber(boolValue: true).intValue == 1,
            // so intValue alone incorrectly accepts boolean true.
            // CFGetTypeID disambiguates: CFBooleanGetTypeID() ≠ CFNumberGetTypeID().
            guard
                let number = contentAvailable as? NSNumber,
                CFGetTypeID(number) == CFNumberGetTypeID(),
                number.intValue == 1
            else {
                throw PushError.opaquePayloadViolation(
                    "\"content-available\" must be integer 1 (not boolean true or other value), got \(contentAvailable)"
                )
            }
        }
    }

#endif // os(iOS) || os(macOS)
