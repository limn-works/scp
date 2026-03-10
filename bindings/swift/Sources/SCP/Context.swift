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
    public typealias CreateFn = @Sendable (
        _ contextId: String,
        _ ceiling: [String]
    ) async throws -> any ContextHandleProtocol

    /// The closure type for sending a message. Injected for testability.
    public typealias SendFn = @Sendable (
        _ handle: any ContextHandleProtocol,
        _ payload: Data
    ) async throws -> Void

    /// The closure type for subscribing to messages. Injected for testability.
    public typealias SubscribeFn = @Sendable (
        _ handle: any ContextHandleProtocol,
        _ listener: any MessageListener
    ) -> Void

    /// The closure type for leaving a context. Injected for testability.
    public typealias LeaveFn = @Sendable (
        _ handle: any ContextHandleProtocol
    ) async throws -> Void

    /// The closure type for closing a context. Injected for testability.
    public typealias CloseFn = @Sendable (
        _ handle: any ContextHandleProtocol
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
/// by Apple as safe to call from any context). See `.docs/standards/swift.md`
/// for the UniFFI callback exception to the `@unchecked Sendable` prohibition.
///
/// See ADR-026 §`MessageListenerAdapter` for the design.
private final class MessageListenerAdapter: MessageListener, @unchecked Sendable {
    private let continuation: AsyncStream<Message>.Continuation

    init(continuation: AsyncStream<Message>.Continuation) {
        self.continuation = continuation
    }

    func onMessage(message: Message) {
        continuation.yield(message)
    }

    func onError(error _: ScpError) {
        // Finish the stream on error. Consumers detect end-of-stream via
        // the `for await` loop terminating. The specific error is not
        // propagated through AsyncStream (which has no error channel);
        // consumers should check context state if they need error details.
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
/// Create a context via the ``create(contextId:ceiling:)`` factory method (or,
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

    // MARK: - Internal state

    /// The opaque UniFFI handle to the Rust context.
    ///
    /// Internal visibility so that extensions in other files (Tools.swift,
    /// etc.) can cast to ``ContextHandle`` for UniFFI bridge calls.
    let handle: any ContextHandleProtocol

    /// The continuation for the active message stream, if any.
    /// Retained so that ``close()`` and ``leave()`` can finish the stream.
    private var streamContinuation: AsyncStream<Message>.Continuation?

    // MARK: - Bridge function references (injected for testability)

    private let sendFn: ContextBridge.SendFn
    private let subscribeFn: ContextBridge.SubscribeFn
    private let leaveFn: ContextBridge.LeaveFn
    private let closeFn: ContextBridge.CloseFn

    // MARK: - Initialization

    /// Creates a `Context` wrapping an existing UniFFI handle.
    ///
    /// This initializer is `internal` — production callers use
    /// ``create(contextId:ceiling:)`` or `SCP.createContext(params:)`.
    ///
    /// - Parameters:
    ///   - handle: The opaque UniFFI context handle.
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
        handle: any ContextHandleProtocol,
        contextId: String? = nil,
        creatorDid: String? = nil,
        initialState: ContextState? = nil,
        sendFn: @escaping ContextBridge.SendFn,
        subscribeFn: @escaping ContextBridge.SubscribeFn,
        leaveFn: @escaping ContextBridge.LeaveFn,
        closeFn: @escaping ContextBridge.CloseFn
    ) {
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
    }

    // MARK: - deinit

    deinit {
        // Safety net: schedule close if the caller forgot to call it explicitly.
        // `try?` intentionally suppresses errors in the deinit path. The detached
        // task captures only the handle and closeFn (both Sendable) — it does not
        // capture `self`, which would be invalid in deinit.
        let capturedHandle = handle
        let capturedCloseFn = closeFn
        streamContinuation?.finish()
        Task.detached {
            try? await capturedCloseFn(capturedHandle)
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
    ///   - contextId: A unique identifier for the new context.
    ///   - ceiling: The capability ceiling for this context (e.g.,
    ///     `["messages:read", "messages:write"]`).
    ///   - createFn: Bridge function for context creation. Defaults to a
    ///     placeholder that will be replaced by real UniFFI bindings.
    ///   - sendFn: Bridge function for sending messages.
    ///   - subscribeFn: Bridge function for subscribing to messages.
    ///   - leaveFn: Bridge function for leaving the context.
    ///   - closeFn: Bridge function for closing the context.
    /// - Returns: A new `Context` in the ``ContextState/active`` state.
    /// - Throws: ``ScpError/Context(message:code:)`` if context creation fails.
    static func create( // swiftlint:disable:this function_parameter_count
        contextId: String,
        ceiling: [String],
        createFn: ContextBridge.CreateFn,
        sendFn: @escaping ContextBridge.SendFn,
        subscribeFn: @escaping ContextBridge.SubscribeFn,
        leaveFn: @escaping ContextBridge.LeaveFn,
        closeFn: @escaping ContextBridge.CloseFn
    ) async throws -> Context {
        let handle = try await createFn(contextId, ceiling)
        return Context(
            handle: handle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
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
    /// - Throws: ``ScpError/Context(message:code:)`` with code `"SCP-CTX-2001"`
    ///   if the context is not active, or if the bridge send operation fails.
    public func send(_ payload: Data) async throws {
        guard state == .active else {
            throw ScpError.Context(
                message: "Context is not active",
                code: "SCP-CTX-2001"
            )
        }
        try await sendFn(handle, payload)
    }

    /// An `AsyncStream` of incoming messages in this context.
    ///
    /// Returns an `AsyncStream` backed by a UniFFI subscription. The stream
    /// yields ``Message`` values as they arrive and finishes when the context
    /// is closed, left, or the subscription encounters an error.
    ///
    /// Only one active message stream per context is supported. Accessing this
    /// property while a previous stream is still active throws
    /// ``ScpError/Context(message:code:)`` with code `"SCP-CTX-2002"`.
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
    /// - Throws: ``ScpError/Context(message:code:)`` with code `"SCP-CTX-2002"`
    ///   if a message stream is already active on this context.
    public var messages: AsyncStream<Message> {
        get throws {
            guard streamContinuation == nil else {
                throw ScpError.Context(
                    message: "A message stream is already active on this context. "
                        + "Consume or close the existing stream before creating a new one.",
                    code: "SCP-CTX-2002"
                )
            }

            let (stream, continuation) = AsyncStream<Message>.makeStream()
            streamContinuation = continuation
            let listener = MessageListenerAdapter(continuation: continuation)
            subscribeFn(handle, listener)
            return stream
        }
    }

    /// Leaves this context gracefully.
    ///
    /// The local participant departs from the MLS group. Other members are
    /// notified. After leaving, the context transitions to ``ContextState/closed``
    /// and the message stream finishes.
    ///
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not
    ///   active or the bridge leave operation fails.
    public func leave() async throws {
        guard state == .active else {
            throw ScpError.Context(
                message: "Context is not active",
                code: "SCP-CTX-2001"
            )
        }
        try await leaveFn(handle)
        state = .closed
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
    /// - Throws: ``ScpError/Context(message:code:)`` if the bridge close
    ///   operation fails.
    public func close() async throws {
        guard state == .active else {
            // Closing an already-closed context is idempotent — no error.
            return
        }
        try await closeFn(handle)
        state = .closed
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
/// - Throws: ``ScpError/Context(message:code:)`` if the context is not
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
