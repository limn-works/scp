// ApplePushProvider — APNs push notification registration with opaque silent-push payloads.
//
// This file holds the APNs push adapter for Apple platforms (iOS 17+, macOS 14+).
// ADR-025, the Apple platform adapter, requires this adapter to conform to the
// UniFFI `PushProvider` callback interface in `crates/scp-ffi/uniffi/src/lib.rs`.
// The shipped actor does not conform yet (ADR-025 acceptance criterion 4).
//
// ## Architecture
//
// `ApplePushProvider` is a Swift actor that turns the AppDelegate callbacks that
// deliver an APNs token into one `async` call. ADR-025 has an `ApplePlatformAdapter`
// assemble the four platform providers and inject them into the Rust engine at SDK
// initialisation. No `ApplePlatformAdapter` exists yet, so no code injects this
// actor into the Rust engine.
//
// ## APNs Payload Opacity (§10.7)
//
// The relay sends **only** `{"aps": {"content-available": 1}}` — a silent push.
// No context ID, sender DID, message preview, or any other metadata may appear
// in the payload. Silent push wakes the app in the background. §10.7 then has the
// device connect to its relays and pull pending encrypted envelopes; no Rust code
// calls `handleNotification(payload:)` yet, so nothing performs that pull today.
// Apple learns only that the device received a notification at a specific time.
//
// `handleNotification(payload:)` **enforces** this invariant on receipt: a JSON
// object whose bytes differ from `{"aps":{"content-available":1}}` by anything but
// whitespace between tokens is rejected with ``PushError/opaquePayloadViolation``.
// ADR-025 criterion 4 names this payload for APNs.
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
    /// ADR-025 in `.docs/adrs/phase-5.md` requires this actor to conform to the
    /// UniFFI-generated `PushProvider` protocol (ADR-021), and this actor does
    /// not conform yet: that protocol names its registration method
    /// `registerPush()` and declares `ScpError` as its error type, while this
    /// actor names it `register()` and throws `PushError`. UniFFI panics on the
    /// Rust side when a callback throws a type the callback does not declare,
    /// so the conformance has to translate each `PushError` to an `ScpError`.
    /// Acceptance criterion 4 of ADR-025 records this gap.
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
    /// let token = try await pushProvider.register()
    /// ```
    public actor ApplePushProvider {
        // MARK: Internal state

        /// Pending continuation waiting for the APNs device token or registration error.
        ///
        /// Set by ``register()`` and consumed (exactly once) by ``tokenDidRegister(_:)``
        /// or ``registrationDidFail(_:)``. After consumption it is set back to `nil`.
        private var tokenContinuation: CheckedContinuation<Data, Error>?

        /// Asks the platform to start APNs registration. ``register()`` schedules
        /// it on the main actor and then suspends without waiting for it to run,
        /// so the call can run after ``hasPendingRegistration`` becomes `true`.
        private let requestRemoteNotifications: @MainActor @Sendable () -> Void

        /// The wake signal ``handleNotification(payload:)`` returns for every
        /// payload it accepts: the UTF-8 bytes of `{"aps":{"content-available":1}}`.
        ///
        /// The method returns this constant, not the received bytes, because
        /// accepted bytes can still carry whitespace the relay chose.
        static let wakeSignal = Data(#"{"aps":{"content-available":1}}"#.utf8)

        /// `true` while a ``register()`` call is suspended waiting for
        /// ``tokenDidRegister(_:)`` or ``registrationDidFail(_:)``.
        var hasPendingRegistration: Bool {
            tokenContinuation != nil
        }

        // MARK: Initialiser

        /// Creates a new `ApplePushProvider` that registers through the shared
        /// application's `registerForRemoteNotifications()`.
        ///
        /// ADR-025 has `ApplePlatformAdapter.make()` call this initialiser once.
        /// That factory does not exist yet.
        public init() {
            requestRemoteNotifications = {
                #if canImport(UIKit)
                    UIApplication.shared.registerForRemoteNotifications()
                #elseif canImport(AppKit)
                    NSApplication.shared.registerForRemoteNotifications()
                #endif
            }
        }

        /// Creates an `ApplePushProvider` that calls `requestRemoteNotifications`
        /// in place of the shared application's `registerForRemoteNotifications()`.
        /// A `swift test` host holds no APNs entitlement, so the callback tests
        /// pass a closure that does nothing, suspend ``register()``, and drive
        /// the AppDelegate callbacks themselves.
        init(requestRemoteNotifications: @escaping @MainActor @Sendable () -> Void) {
            self.requestRemoteNotifications = requestRemoteNotifications
        }

        // MARK: APNs registration and payload handling

        /// Register for APNs push notifications and return the device token bytes.
        ///
        /// Calls the platform-specific `registerForRemoteNotifications()` method and
        /// suspends until the AppDelegate delivers the token (or an error) via
        /// ``tokenDidRegister(_:)`` / ``registrationDidFail(_:)``. Races a 30-second
        /// timeout so callers are never blocked indefinitely.
        ///
        /// - Returns: The raw APNs device token bytes (typically 32 bytes). No Rust
        ///   code calls this method yet.
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

            // Schedule registration on the main actor. The main actor runs it
            // whenever it gets to it, which can be after this call suspends.
            let request = requestRemoteNotifications
            Task { @MainActor in
                request()
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
        /// Validates that `payload` is the opaque `{"aps": {"content-available": 1}}` payload
        /// ADR-025 criterion 4 names for APNs, which meets the §10.7 rule that a push
        /// payload carries no context ID, sender identifier, or other metadata. Any
        /// additional field in the payload — at the top level or nested inside `aps`,
        /// including one carried by a repeated key — is rejected with
        /// ``PushError/opaquePayloadViolation``.
        ///
        /// When the payload is valid, the method returns ``wakeSignal``, a fixed byte
        /// string, and never the received bytes, so a caller receives no byte the relay
        /// chose. The permitted payload carries no context ID, sender identifier, or
        /// message count, so the wake signal carries none. No Rust code calls this
        /// method yet.
        ///
        /// - Parameter payload: The raw JSON bytes delivered by APNs.
        /// - Returns: ``wakeSignal``, the UTF-8 bytes of `{"aps":{"content-available":1}}`.
        ///
        /// - Throws:
        ///   - ``PushError/invalidPayload(_:)`` if the bytes cannot be parsed as JSON or the
        ///     top-level structure is not a dictionary.
        ///   - ``PushError/opaquePayloadViolation(_:)`` if the payload exceeds 4096 bytes,
        ///     or is a JSON object whose bytes differ from `{"aps":{"content-available":1}}`
        ///     by anything but JSON whitespace between tokens: any other field, a repeated
        ///     key, or any `content-available` value other than the token `1`.
        public func handleNotification(payload: Data) throws -> Data {
            try validateOpaquePayload(payload)
            return Self.wakeSignal
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
        /// Validation rules, in the order they run:
        /// 1. The payload is at most 4096 bytes, the APNs maximum.
        /// 2. The payload parses as JSON, and its root is a JSON object.
        /// 3. The payload bytes, with JSON whitespace (space, tab, line feed,
        ///    carriage return) removed outside string literals, equal
        ///    ``wakeSignal``.
        ///
        /// Rules 1 and 3 together decide which payload is accepted: rule 3
        /// decides among payloads of at most 4096 bytes, and rule 1 rejects a
        /// payload rule 3 would accept when whitespace between its tokens takes
        /// it past 4096 bytes. Rule 3 reads the received
        /// bytes, not the dictionary `JSONSerialization` builds, because
        /// `JSONSerialization` keeps one value for a key the object repeats: a
        /// second `aps` or `content-available` member carrying a context ID
        /// parses to the permitted object. Rule 3 rejects that payload, and any
        /// other field, a boolean, a fraction such as `1.0` or `1.5`, an escaped
        /// key, or any value other than the token `1`, because none of them
        /// reduces to ``wakeSignal``. Rule 3 keeps whitespace inside a string
        /// literal, so the key `"a ps"` stays distinct from `"aps"`. It finds
        /// string literals by toggling on each `"` byte; an escaped quote would
        /// throw that count off, but its backslash is never removed and
        /// ``wakeSignal`` holds no backslash, so such a payload never matches.
        ///
        /// Every payload rule 3 accepts is ``wakeSignal`` with whitespace
        /// between its tokens, which is a JSON object, so rule 2 rejects no
        /// payload rule 3 would accept. Rule 2 decides only which error a
        /// caller receives: ``PushError/invalidPayload(_:)`` for bytes that are
        /// not a JSON object, ``PushError/opaquePayloadViolation(_:)`` for a
        /// JSON object other than the permitted one.
        ///
        /// - Parameter payload: Raw JSON bytes to validate.
        /// - Throws: ``PushError/invalidPayload(_:)`` or ``PushError/opaquePayloadViolation(_:)``.
        private func validateOpaquePayload(_ payload: Data) throws {
            // Rule 1: APNs payload limit is 4 KB for standard push; reject oversized payloads early.
            let maxPayloadBytes = 4096
            guard payload.count <= maxPayloadBytes else {
                throw PushError.opaquePayloadViolation(
                    "payload size \(payload.count) bytes exceeds 4 KB APNs maximum"
                )
            }

            // Rule 2: the bytes are a JSON object.
            let json: Any
            do {
                json = try JSONSerialization.jsonObject(with: payload, options: [])
            } catch {
                throw PushError.invalidPayload(error.localizedDescription)
            }
            guard json is [String: Any] else {
                throw PushError.invalidPayload("payload root is not a JSON object")
            }

            // Rule 3: the received bytes, whitespace outside string literals
            // removed, are the permitted payload.
            var stripped = Data(capacity: payload.count)
            var inString = false
            for byte in payload {
                if byte == 0x22 {
                    inString.toggle()
                } else if !inString, byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D {
                    continue
                }
                stripped.append(byte)
            }
            guard stripped == Self.wakeSignal else {
                throw PushError.opaquePayloadViolation(
                    "payload bytes differ from {\"aps\":{\"content-available\":1}} by more than whitespace between tokens"
                )
            }
        }
    }

#endif // os(iOS) || os(macOS)
