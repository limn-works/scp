import Foundation

// ContextState and ContextHandleProtocol are now defined by UniFFI in ScpBindings.swift.
//
// UniFFI ContextState: .creating, .active, .closing, .closed, .expired
// UniFFI ContextHandleProtocol: contextId() -> String, creatorDid() -> String, state() throws -> String
// UniFFI MessageListener: onMessage(message:), onError(error:), onComplete()

// MARK: - ContextBridge (UniFFI function stubs)

/// Namespace for UniFFI bridge function stubs. Each function maps 1:1 to a Rust
/// FFI export. These will be replaced by auto-generated free functions in
/// ``ScpBindings`` when the XCFramework is built (SCP-103).
///
/// See ADR-021 for the bridge function surface and ADR-026 for the delegation
/// pattern (every Swift SDK method calls exactly one bridge function).
public enum ContextBridge {
    /// The closure type for context creation. Injected for testability.
    ///
    /// Matches the UniFFI `contextCreate(identity:params:)` bridge function.
    /// Takes the creating identity and context parameters, returns a handle.
    public typealias CreateFn = @Sendable (
        _ identity: Identity,
        _ params: ContextParams
    ) async throws -> any ContextHandleProtocol

    /// Default create function — delegates to UniFFI ``contextCreate(identity:params:)``.
    public static let defaultCreate: CreateFn = { identity, params in
        try await contextCreate(identity: identity, params: params)
    }

    /// The closure type for sending a message. Injected for testability.
    public typealias SendFn = @Sendable (
        _ handle: ContextHandle,
        _ identity: Identity,
        _ payload: Data
    ) async throws -> Void

    /// The closure type for subscribing to messages. Injected for testability.
    public typealias SubscribeFn = @Sendable (
        _ handle: ContextHandle,
        _ listener: any MessageListener
    ) -> Void

    /// The closure type for leaving a context. Injected for testability.
    public typealias LeaveFn = @Sendable (
        _ handle: ContextHandle,
        _ identity: Identity
    ) async throws -> Void

    /// The closure type for closing a context. Injected for testability.
    public typealias CloseFn = @Sendable (
        _ handle: ContextHandle,
        _ identity: Identity
    ) async throws -> Void

    /// The closure type for joining an existing context. Injected for testability.
    public typealias JoinFn = @Sendable (
        _ handle: ContextHandle,
        _ identity: Identity
    ) async throws -> Void

    /// Default join function — delegates to UniFFI ``contextJoin``.
    public static let defaultJoin: JoinFn = { handle, identity in
        try await contextJoin(handle: handle, identity: identity)
    }

    /// Default send function — delegates to UniFFI ``contextSend``.
    public static let defaultSend: SendFn = { handle, identity, payload in
        try await contextSend(handle: handle, identity: identity, payload: payload)
    }

    /// Default leave function — delegates to UniFFI ``contextLeave``.
    public static let defaultLeave: LeaveFn = { handle, identity in
        try await contextLeave(handle: handle, identity: identity)
    }

    /// Default close function — delegates to UniFFI ``contextClose``.
    public static let defaultClose: CloseFn = { handle, identity in
        try await contextClose(handle: handle, identity: identity)
    }

    /// The closure type for setting economic policy. Injected for testability.
    public typealias SetEconomicPolicyFn = @Sendable (
        _ handle: ContextHandle,
        _ policyJson: String
    ) throws -> Void

    /// The closure type for getting economic policy. Injected for testability.
    public typealias GetEconomicPolicyFn = @Sendable (
        _ handle: ContextHandle
    ) throws -> String?

    /// Default set economic policy function — delegates to UniFFI ``setEconomicPolicy``.
    public static let defaultSetEconomicPolicy: SetEconomicPolicyFn = { handle, policyJson in
        try setEconomicPolicy(handle: handle, policyJson: policyJson)
    }

    /// Default get economic policy function — delegates to UniFFI ``getEconomicPolicy``.
    public static let defaultGetEconomicPolicy: GetEconomicPolicyFn = { handle in
        try getEconomicPolicy(handle: handle)
    }
}

// MARK: - SharedError

/// Thread-safe container for the last error received by a message stream.
///
/// `MessageListenerAdapter` writes the error from the Rust callback thread;
/// the `Context` actor reads it from its own isolation domain. `NSLock`
/// provides the cross-isolation synchronization. This is `@unchecked Sendable`
/// because access is guarded by the lock — see `.docs/adrs/phase-5.md`
/// §ADR-026 acceptance criterion 11.
private final class SharedError: @unchecked Sendable {
    private var error: ScpError?
    private let lock = NSLock()

    func set(_ error: ScpError) {
        lock.lock()
        defer { lock.unlock() }
        self.error = error
    }

    func get() -> ScpError? {
        lock.lock()
        defer { lock.unlock() }
        return error
    }

    func reset() {
        lock.lock()
        defer { lock.unlock() }
        error = nil
    }
}

// MARK: - MessageListenerAdapter

/// Adapts the UniFFI ``MessageListener`` callback interface to an
/// ``AsyncStream<Message>.Continuation``.
///
/// Each incoming message from the Rust subscription is yielded into the stream.
/// Errors and completion signals finish the stream. The adapter is retained by
/// the Rust subscription for the lifetime of the stream.
///
/// Note: This class uses `@unchecked Sendable` because it is accessed from the
/// Rust callback thread (via UniFFI) and the actor-isolated stream consumer.
/// The `AsyncStream.Continuation` it wraps is itself thread-safe (documented
/// by Apple as safe to call from any context). See `.docs/adrs/phase-5.md`
/// §ADR-026 acceptance criterion 11.
///
/// See ADR-026 §`MessageListenerAdapter` for the design.
private final class MessageListenerAdapter: MessageListener, @unchecked Sendable {
    private let continuation: AsyncStream<Message>.Continuation
    private let sharedError: SharedError

    init(continuation: AsyncStream<Message>.Continuation, sharedError: SharedError) {
        self.continuation = continuation
        self.sharedError = sharedError
    }

    func onMessage(message: Message) {
        continuation.yield(message)
    }

    func onError(error: ScpError) {
        // Store the error so consumers can distinguish connection failures
        // from clean stream termination via `Context.lastError`.
        sharedError.set(error)
        continuation.finish()
    }

    func onComplete() {
        continuation.finish()
    }
}

// MARK: - Context

/// An active SCP context. Send messages, receive streams, and manage lifecycle.
///
/// `Context` is an actor providing thread-safe access to mutable protocol state
/// (MLS group keys, sender keys, connection handles). All public methods are
/// `async throws` and delegate to exactly one UniFFI bridge function — no
/// protocol logic lives in the Swift layer.
///
/// ## Lifecycle
///
/// Create a context via the ``create(identity:params:)`` factory method (or,
/// in production, via `SCP.createContext(params:)` from ADR-026). Use
/// ``send(_:)`` to publish messages and ``messages`` to consume them as an
/// `AsyncStream`. Call ``leave()`` to depart gracefully or ``close()`` to
/// terminate the context for all members.
///
/// ## Resource management
///
/// SCP contexts hold live crypto state (MLS group keys, sender AES-256 keys)
/// that must be zeroed on deallocation. ``close()`` is the user-visible method
/// for graceful teardown. `deinit` is the safety net — it schedules cleanup via
/// a detached `Task` to prevent resource leaks when a context is dropped without
/// explicit close. Always prefer calling ``close()`` explicitly.
///
/// ## Streaming
///
/// ``messages`` returns an `AsyncStream<Message>` — the Swift 6 structured
/// concurrency primitive for push-based sequences. Consume it with `for await`.
/// The stream finishes automatically when the context is closed or left.
///
/// See ADR-026 for the full Swift SDK design and `.docs/scaffold/swift.md` for
/// the package layout.
public actor Context {
    // MARK: - Public properties

    /// The unique identifier of this context.
    public let contextId: String

    /// The DID of the context creator, cached from the handle at init time.
    public let creatorDid: String

    /// The current lifecycle state of this context.
    public internal(set) var state: ContextState

    /// The last error received by the message stream, if any.
    ///
    /// When the message subscription encounters an error (e.g. a transport
    /// failure), ``MessageListenerAdapter/onError(error:)`` stores it here
    /// before finishing the stream. Consumers can check this property after
    /// the `for await` loop terminates to distinguish connection failures
    /// from clean stream close.
    ///
    /// The value is `nil` when no error has occurred, or when the stream
    /// ended normally via ``onComplete()``, ``leave()``, or ``close()``.
    public var lastError: ScpError? {
        streamError.get()
    }

    // MARK: - Internal state

    /// The identity of the local participant in this context.
    ///
    /// Internal visibility so that extensions in other files (Tools.swift,
    /// etc.) can access the identity for UniFFI bridge calls that require it.
    let identity: Identity

    /// The opaque UniFFI handle to the Rust context.
    ///
    /// Internal visibility so that extensions in other files (Tools.swift,
    /// etc.) can access the handle for UniFFI bridge calls.
    let handle: ContextHandle

    /// The continuation for the active message stream, if any.
    /// Retained so that ``close()`` and ``leave()`` can finish the stream.
    private var streamContinuation: AsyncStream<Message>.Continuation?

    /// Thread-safe error storage shared with ``MessageListenerAdapter``.
    /// The adapter writes errors from the Rust callback thread; the actor
    /// reads them via the ``lastError`` computed property.
    private let streamError = SharedError()

    /// Whether ``close()`` or ``leave()`` has already been called.
    /// Checked in `deinit` to avoid redundant cleanup. Marked
    /// `nonisolated(unsafe)` because `deinit` cannot access actor-isolated
    /// storage — the flag is only read in `deinit` after all actor-isolated
    /// methods have finished.
    nonisolated(unsafe) var didClose = false

    // MARK: - Bridge function references (injected for testability)

    private let sendFn: ContextBridge.SendFn
    private let subscribeFn: ContextBridge.SubscribeFn
    private let leaveFn: ContextBridge.LeaveFn
    private let closeFn: ContextBridge.CloseFn
    private let setEconomicPolicyFn: ContextBridge.SetEconomicPolicyFn
    private let getEconomicPolicyFn: ContextBridge.GetEconomicPolicyFn

    // MARK: - Initialization

    /// Creates a `Context` wrapping an existing UniFFI handle.
    ///
    /// This initializer is `internal` — production callers use
    /// ``create(identity:params:)`` or `SCP.createContext(params:)`.
    ///
    /// - Parameters:
    ///   - handle: The opaque UniFFI context handle.
    ///   - identity: The ``Identity`` of the local participant.
    ///   - contextId: Optional override for the context ID. When `nil`,
    ///     the ID is read from the handle. Pass explicitly in tests where
    ///     the handle has no backing FFI pointer.
    ///   - initialState: Optional override for the initial state. When
    ///     `nil`, the state is read from the handle (defaulting to
    ///     ``ContextState/active`` if the handle throws).
    ///   - sendFn: Bridge function for sending messages.
    ///   - subscribeFn: Bridge function for subscribing to messages.
    ///   - leaveFn: Bridge function for leaving the context.
    ///   - closeFn: Bridge function for closing the context.
    init(
        handle: ContextHandle,
        identity: Identity,
        contextId: String? = nil,
        creatorDid: String? = nil,
        initialState: ContextState? = nil,
        sendFn: @escaping ContextBridge.SendFn = ContextBridge.defaultSend,
        subscribeFn: @escaping ContextBridge.SubscribeFn,
        leaveFn: @escaping ContextBridge.LeaveFn = ContextBridge.defaultLeave,
        closeFn: @escaping ContextBridge.CloseFn = ContextBridge.defaultClose,
        setEconomicPolicyFn: @escaping ContextBridge.SetEconomicPolicyFn
            = ContextBridge.defaultSetEconomicPolicy,
        getEconomicPolicyFn: @escaping ContextBridge.GetEconomicPolicyFn
            = ContextBridge.defaultGetEconomicPolicy
    ) {
        self.identity = identity
        self.handle = handle
        if let contextId {
            self.contextId = contextId
        } else {
            self.contextId = handle.contextId()
        }
        if let creatorDid {
            self.creatorDid = creatorDid
        } else {
            self.creatorDid = handle.creatorDid()
        }
        if let initialState {
            state = initialState
        } else {
            // UniFFI ContextHandleProtocol.state() throws, so use try? with a fallback.
            let stateString = (try? handle.state()) ?? "active"
            switch stateString {
            case "creating": state = .creating
            case "active": state = .active
            case "closing": state = .closing
            case "closed": state = .closed
            case "expired": state = .expired
            default: state = .active
            }
        }
        self.sendFn = sendFn
        self.subscribeFn = subscribeFn
        self.leaveFn = leaveFn
        self.closeFn = closeFn
        self.setEconomicPolicyFn = setEconomicPolicyFn
        self.getEconomicPolicyFn = getEconomicPolicyFn
    }

    // MARK: - deinit

    deinit {
        // Safety net: schedule close if the caller forgot to call it explicitly.
        // `try?` intentionally suppresses errors in the deinit path. The detached
        // task captures only the handle, identity, and closeFn (all Sendable) — it
        // does not capture `self`, which would be invalid in deinit.
        streamContinuation?.finish()
        guard !didClose else { return }
        let capturedHandle = handle
        let capturedIdentity = identity
        let capturedCloseFn = closeFn
        Task.detached {
            try? await capturedCloseFn(capturedHandle, capturedIdentity)
        }
    }

    // MARK: - Factory

    /// Creates a new SCP context.
    ///
    /// This is the primary factory method for creating contexts. In production,
    /// callers typically use `SCP.createContext(params:)` which delegates to
    /// this method after injecting the identity and bridge functions.
    ///
    /// - Parameters:
    ///   - identity: The ``Identity`` of the context creator. Provides the DID
    ///     and key material for MLS group formation.
    ///   - params: The ``ContextParams`` governing the new context (ceiling,
    ///     governance, memory scope, TTL, promotability, min protocol version).
    ///   - createFn: Bridge function for context creation.
    ///   - sendFn: Bridge function for sending messages.
    ///   - subscribeFn: Bridge function for subscribing to messages.
    ///   - leaveFn: Bridge function for leaving the context.
    ///   - closeFn: Bridge function for closing the context.
    /// - Returns: A new `Context` in the ``ContextState/active`` state.
    /// - Throws: ``ScpError/Context(msg:code:)`` if context creation fails.
    static func create(
        identity: Identity,
        params: ContextParams,
        createFn: ContextBridge.CreateFn = ContextBridge.defaultCreate,
        sendFn: @escaping ContextBridge.SendFn = ContextBridge.defaultSend,
        subscribeFn: @escaping ContextBridge.SubscribeFn,
        leaveFn: @escaping ContextBridge.LeaveFn = ContextBridge.defaultLeave,
        closeFn: @escaping ContextBridge.CloseFn = ContextBridge.defaultClose,
        setEconomicPolicyFn: @escaping ContextBridge.SetEconomicPolicyFn
            = ContextBridge.defaultSetEconomicPolicy,
        getEconomicPolicyFn: @escaping ContextBridge.GetEconomicPolicyFn
            = ContextBridge.defaultGetEconomicPolicy,
        contextId: String? = nil,
        creatorDid: String? = nil,
        initialState: ContextState? = nil
    ) async throws -> Context {
        let rawHandle = try await createFn(identity, params)
        guard let handle = rawHandle as? ContextHandle else {
            throw ScpError.Context(
                msg: "createFn returned a non-concrete ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return Context(
            handle: handle,
            identity: identity,
            contextId: contextId,
            creatorDid: creatorDid,
            initialState: initialState,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn,
            setEconomicPolicyFn: setEconomicPolicyFn,
            getEconomicPolicyFn: getEconomicPolicyFn
        )
    }

    // MARK: - Public methods

    /// Sends a message payload to this context.
    ///
    /// The payload is encrypted via MLS and delivered to all context members
    /// through the Rust protocol engine. The bridge function handles encryption,
    /// sequencing, and transport.
    ///
    /// - Parameter payload: The raw message data to send.
    /// - Throws: ``ScpError/Context(msg:code:)`` with code `"SCP-CTX-2001"`
    ///   if the context is not active, or if the bridge send operation fails.
    public func send(_ payload: Data) async throws {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2001"
            )
        }
        try await sendFn(handle, identity, payload)
    }

    /// Sets the economic policy for this context (spec section 19).
    ///
    /// Validates the JSON against the `EconomicPolicy` schema before storing.
    ///
    /// - Parameter policyJson: The economic policy as a JSON string.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active,
    ///   or ``ScpError/Validation(msg:code:)`` if the JSON is invalid.
    public func setEconomicPolicy(_ policyJson: String) throws {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2001"
            )
        }
        try setEconomicPolicyFn(handle, policyJson)
    }

    /// Returns the economic policy for this context as a JSON string, or `nil`.
    ///
    /// - Returns: The economic policy JSON string, or `nil` if no policy is set.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active.
    public func getEconomicPolicy() throws -> String? {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2001"
            )
        }
        return try getEconomicPolicyFn(handle)
    }

    /// An `AsyncStream` of incoming messages in this context.
    ///
    /// Returns an `AsyncStream` backed by a UniFFI subscription. The stream
    /// yields ``Message`` values as they arrive and finishes when the context
    /// is closed, left, or the subscription encounters an error.
    ///
    /// When the stream terminates due to an error (e.g. a transport failure),
    /// the error is stored in ``lastError``. Check this property after the
    /// `for await` loop exits to distinguish error termination from clean close:
    ///
    /// ```swift
    /// let stream = try await context.messages
    /// for await message in stream {
    ///     print(message.senderDid, message.payload)
    /// }
    /// if let error = await context.lastError {
    ///     // Connection failure or subscription error
    /// }
    /// ```
    ///
    /// Only one active message stream per context is supported. Accessing this
    /// property while a previous stream is still active throws
    /// ``ScpError/Context(msg:code:)`` with code `"SCP-CTX-2003"`.
    /// To create a new stream, first ``close()`` or ``leave()`` the context
    /// (which finishes the existing stream), or consume the existing stream
    /// to completion.
    ///
    /// Usage:
    /// ```swift
    /// let stream = try await context.messages
    /// for await message in stream {
    ///     print(message.senderDid, message.payload)
    /// }
    /// ```
    ///
    /// - Throws: ``ScpError/Context(msg:code:)`` with code `"SCP-CTX-2001"`
    ///   if the context is not active, or `"SCP-CTX-2003"` if a message stream
    ///   is already active on this context.
    public var messages: AsyncStream<Message> {
        get throws {
            guard state == .active else {
                throw ScpError.Context(
                    msg: "Context is not active",
                    code: "SCP-CTX-2001"
                )
            }
            guard streamContinuation == nil else {
                throw ScpError.Context(
                    msg: "A message stream is already active on this context. "
                        + "Consume or close the existing stream before creating a new one.",
                    code: "SCP-CTX-2003"
                )
            }

            streamError.reset()
            let (stream, continuation) = AsyncStream<Message>.makeStream()
            streamContinuation = continuation
            continuation.onTermination = { [weak self] _ in
                // Clear the continuation when the stream finishes naturally so
                // a new stream can be created on re-subscribe.
                guard let self else { return }
                Task { await self.clearStreamContinuation() }
            }
            let listener = MessageListenerAdapter(continuation: continuation, sharedError: streamError)
            subscribeFn(handle, listener)
            return stream
        }
    }

    /// Clears the stream continuation reference. Called from `onTermination`
    /// to allow a new message stream after the previous one finishes.
    private func clearStreamContinuation() {
        streamContinuation = nil
    }

    /// Leaves this context gracefully.
    ///
    /// The local participant departs from the MLS group. Other members are
    /// notified. After leaving, the context transitions to ``ContextState/closed``
    /// and the message stream finishes.
    ///
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not
    ///   active or the bridge leave operation fails.
    public func leave() async throws {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2001"
            )
        }
        try await leaveFn(handle, identity)
        state = .closed
        didClose = true
        streamContinuation?.finish()
        streamContinuation = nil
    }

    /// Closes this context, terminating it for all members.
    ///
    /// This is the explicit cleanup method. It leaves the MLS group, flushes
    /// the event log, closes the transport connection, and zeros crypto state.
    /// After close, the context transitions to ``ContextState/closed`` and the
    /// message stream finishes.
    ///
    /// Always call `close()` when done with a context. `deinit` provides a
    /// safety net but should not be relied upon for timely cleanup.
    ///
    /// - Throws: ``ScpError/Context(msg:code:)`` if the bridge close
    ///   operation fails.
    public func close() async throws {
        guard state == .active else {
            // Closing an already-closed context is idempotent — no error.
            return
        }
        try await closeFn(handle, identity)
        state = .closed
        didClose = true
        streamContinuation?.finish()
        streamContinuation = nil
    }
}

// MARK: - Context Join (free function)

/// Joins an existing SCP context.
///
/// Delegates to the UniFFI ``contextJoin`` bridge function. The identity
/// provides the key package for MLS group admission.
///
/// - Parameters:
///   - handle: The ``ContextHandle`` for the context to join.
///   - identity: The ``Identity`` joining the context.
///   - joinFn: Bridge function override for testing.
/// - Throws: ``ScpError/Context(msg:code:)`` if the context is not
///   in active state or the join operation fails.
///
/// ## Provenance
///
/// - ADR-021 (UniFFI Bridge)
/// - ADR-026 (Swift SDK)
/// - Spec section 5 (Context Lifecycle)
public func joinContext(
    handle: ContextHandle,
    identity: Identity,
    joinFn: ContextBridge.JoinFn = ContextBridge.defaultJoin
) async throws {
    try await joinFn(handle, identity)
}

// MARK: - App Sandboxing (spec §8.4.1, §8.4.2, issue #595)

/// Result of validating a capability declaration.
public struct DeclarationValidationResult: Sendable {
    /// Whether the validation passed.
    public let valid: Bool
    /// Capabilities granted to the app (if valid).
    public let grantedCapabilities: [String]
    /// Error message if validation failed, nil otherwise.
    public let error: String?
    /// The DID of the app from the declaration.
    public let appDid: String
}

/// Capability-restricted context handle (spec §8.4.2).
///
/// Wraps a `ContextHandle` with a whitelist of allowed capabilities. All protocol
/// operations must check the whitelist before proceeding. An app cannot access
/// protocol operations beyond its declared capabilities.
///
/// Once created, a `ScopedHandle` cannot gain additional capabilities
/// (no escalation guarantee, spec 8.4.2 rule 4).
public struct ScopedHandle: Sendable {
    /// The wrapped context handle.
    public let handle: ContextHandle
    /// The capabilities granted to this app binding.
    public let grantedCapabilities: [String]
    /// The DID of the app.
    public let appDid: String

    /// Check whether a given capability is allowed.
    public func hasCapability(_ capability: String) -> Bool {
        sandboxCheckCapability(grantedCapabilities: grantedCapabilities, requiredCapability: capability)
    }

    /// Throws ``ScpError`` if the capability is not granted.
    public func checkCapability(_ capability: String) throws {
        guard hasCapability(capability) else {
            throw ScpError.Context(
                msg: "capability denied: \(capability) not granted to app \(appDid)",
                code: "SCP-CTX-2050"
            )
        }
    }
}

/// Returns a context-scoped validation error with the standard code.
private func validationError(_ message: String) -> ScpError {
    ScpError.Context(msg: message, code: "SCP-CTX-2051")
}

/// Extracts a nullable ``String`` from a JSON value (accepts ``String`` or ``NSNull``).
private func extractNullableString(_ value: Any?, field: String) throws -> String? {
    guard let raw = value else { return nil }
    if raw is NSNull { return nil }
    guard let str = raw as? String else {
        throw validationError("validation result '\(field)' has unexpected type (expected String or null)")
    }
    return str
}

/// Parses a validation result JSON string into a ``DeclarationValidationResult``.
///
/// - Parameter resultJson: The JSON string returned by the bridge.
/// - Throws: ``ScpError`` if the JSON is malformed or missing required fields.
private func parseValidationResult(_ resultJson: String) throws -> DeclarationValidationResult {
    guard let data = resultJson.data(using: .utf8) else {
        throw validationError("failed to encode validation result as UTF-8")
    }
    let parsed: Any
    do { parsed = try JSONSerialization.jsonObject(with: data) } catch {
        throw validationError("failed to parse validation result JSON: \(error.localizedDescription)")
    }
    guard let json = parsed as? [String: Any] else {
        throw validationError("validation result JSON is not an object")
    }
    guard let valid = json["valid"] as? Bool else {
        throw validationError("validation result missing or invalid 'valid' field (expected Bool)")
    }
    guard let capabilities = json["granted_capabilities"] as? [String] else {
        throw validationError("missing or invalid 'granted_capabilities' field (expected [String])")
    }
    guard let appDid = json["app_did"] as? String else {
        throw validationError("missing or invalid 'app_did' field (expected String)")
    }
    let errorValue = try extractNullableString(json["error"], field: "error")
    return DeclarationValidationResult(
        valid: valid, grantedCapabilities: capabilities, error: errorValue, appDid: appDid
    )
}

/// Validates a capability declaration against a context ceiling and role capabilities.
///
/// Returns a ``DeclarationValidationResult`` with the validation outcome.
/// See spec §8.4.1.
///
/// - Parameters:
///   - declarationJson: JSON string of the capability declaration.
///   - ceilingCapabilities: List of capability name strings in the context ceiling.
///   - roleCapabilities: List of capability name strings in the agent's role.
/// - Throws: ``ScpError`` if the declaration JSON is malformed.
public func validateCapabilityDeclaration(
    declarationJson: String,
    ceilingCapabilities: [String],
    roleCapabilities: [String]
) throws -> DeclarationValidationResult {
    let resultJson = try sandboxValidateDeclaration(
        declarationJson: declarationJson,
        ceilingCapabilities: ceilingCapabilities,
        roleCapabilities: roleCapabilities
    )
    return try parseValidationResult(resultJson)
}

// MARK: - Invitation Evaluation (#614)

/// The result of evaluating a context invitation through the pipeline.
public nonisolated struct InvitationEvaluationResult: Sendable {
    /// The pipeline decision: ``autoAccept`` or ``promptAgent``.
    public let decision: String

    /// Whether the invitation was auto-accepted.
    public var isAutoAccept: Bool {
        decision == "auto_accept"
    }
}

/// Evaluates a context invitation through the sequential pipeline.
///
/// Runs the 4-step evaluation pipeline:
/// 1. **Template check** -- validates params match the claimed template.
/// 2. **Economic policy check** -- verifies spending capability for paid contexts.
/// 3. **Auto-accept check** -- evaluates trust, TTL cap, and rate limit.
/// 4. **Agent prompt** -- falls through if no auto-accept matches.
///
/// - Parameters:
///   - paramsJson: JSON-serialized ``ContextParams`` from the invitation.
///   - inviterDid: DID string of the identity sending the invitation.
///   - identityDid: DID string of the local identity receiving the invitation.
///   - policyJson: Optional JSON-serialized ``AutoAcceptPolicy``.
///   - spendingJson: Optional JSON-serialized ``SpendingContext``.
///   - trustedDids: Optional array of trusted DID strings.
/// - Returns: An ``InvitationEvaluationResult`` with the pipeline decision.
/// - Throws: ``ScpError`` if evaluation fails.
public func evaluateContextInvitation(
    paramsJson: String,
    inviterDid: String,
    identityDid: String,
    policyJson: String? = nil,
    spendingJson: String? = nil,
    trustedDids: [String] = []
) throws -> InvitationEvaluationResult {
    let decision = try evaluateInvitation(
        paramsJson: paramsJson,
        inviterDid: inviterDid,
        identityDid: identityDid,
        policyJson: policyJson,
        spendingJson: spendingJson,
        trustedDids: trustedDids
    )
    return InvitationEvaluationResult(decision: decision)
}

// MARK: - MetadataRecord Inspection (§5.7.2, #615)

// swiftlint:disable function_parameter_count
/// Serializes a MetadataRecord to a JSON string (spec §5.7.2).
///
/// Delegates to UniFFI ``metadataRecordToJson``.
///
/// - Parameters:
///   - contextId: The context this metadata describes.
///   - sequence: Monotonically increasing sequence number (starts at 1).
///   - signerDid: DID of the admin who signed this record.
///   - timestamp: Unix timestamp in milliseconds.
///   - structuralJson: Structural metadata as a JSON string.
///   - operationalJson: Operational metadata as a JSON string.
///   - signatureHex: Ed25519 signature as hex string (128 hex chars).
/// - Returns: JSON string of the MetadataRecord.
/// - Throws: ``ScpError`` if any input is malformed.
public func serializeMetadataRecord(
    contextId: String,
    sequence: UInt64,
    signerDid: String,
    timestamp: UInt64,
    structuralJson: String,
    operationalJson: String,
    signatureHex: String
) throws -> String {
    try metadataRecordToJson(
        contextId: contextId,
        sequence: sequence,
        signerDid: signerDid,
        timestamp: timestamp,
        structuralJson: structuralJson,
        operationalJson: operationalJson,
        signatureHex: signatureHex
    )
}

// swiftlint:enable function_parameter_count

/// Deserializes a MetadataRecord from a JSON string (spec §5.7.2).
///
/// Delegates to UniFFI ``metadataRecordFromJson``.
///
/// - Parameter jsonStr: JSON string of a MetadataRecord.
/// - Returns: Validated and re-serialized JSON string.
/// - Throws: ``ScpError`` if the JSON is malformed.
public func deserializeMetadataRecord(jsonStr: String) throws -> String {
    try metadataRecordFromJson(jsonStr: jsonStr)
}

// MARK: - Context Template Inspection (§5.14, #615)

/// Gets the canonical ContextParams for a well-known template (spec §5.12.1).
///
/// Delegates to UniFFI ``templateGetParams``.
///
/// - Parameter templateId: Template identifier string.
/// - Returns: JSON string of the canonical ContextParams.
/// - Throws: ``ScpError`` if the template ID is not recognized.
public func getTemplateParams(templateId: String) throws -> String {
    try templateGetParams(templateId: templateId)
}

/// Validates that ContextParams match their template definition.
///
/// Delegates to UniFFI ``validateAgainstTemplate``.
///
/// - Parameter paramsJson: ContextParams as a JSON string.
/// - Returns: `nil` on success, or a string error message on validation failure.
/// - Throws: ``ScpError`` if the JSON is malformed.
public func validateParamsAgainstTemplate(paramsJson: String) throws -> String? {
    try validateAgainstTemplate(paramsJson: paramsJson)
}

/// Validates cross-field invariants for ContextParams regardless of template.
///
/// Delegates to UniFFI ``validateContextParams``.
///
/// - Parameter paramsJson: ContextParams as a JSON string.
/// - Returns: `nil` on success, or a string error message on validation failure.
/// - Throws: ``ScpError`` if the JSON is malformed.
public func validateParams(paramsJson: String) throws -> String? {
    try validateContextParams(paramsJson: paramsJson)
}
