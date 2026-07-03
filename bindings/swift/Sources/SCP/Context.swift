import Foundation

// ContextState and ContextHandleProtocol are now defined by UniFFI in ScpBindings.swift.
//
// UniFFI ContextState: .creating, .active, .closing, .closed, .expired,
//   .migratingOut, .tombstoned, .poisoned (all 8 states — see ADR-049 §10 for
//   .poisoned; `mapStateString` below maps every one, defaulting fail-safe to
//   .poisoned for an unreadable/unrecognized state).
// UniFFI ContextHandleProtocol: contextId() -> String, creatorDid() -> String, state() throws -> String
// UniFFI MessageListener: onMessage(message:), onError(error:), onComplete()

// Phase 4 PR 4 (ADR-048 demolition, #1549): the process-wide
// `Scp.defaultInstance()` and the `ContextBridge` injectable-closure
// namespace have been deleted. `Context` now stores an explicit
// ``SCP`` reference and forwards every bridge call through it —
// callers construct an ``SCP`` and thread it through ``Context/create``
// or the higher-level factory on ``SCP``.

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

    /// The SDK-level ``SCP`` instance that minted ``handle``. Every
    /// UniFFI call made by this actor (and its cross-file extensions)
    /// flows through this reference — there is no process-global
    /// façade after ADR-048 PR 4.
    ///
    /// Internal visibility so extensions in other files (Tools.swift,
    /// Governance.swift, etc.) can reach it without exposing the
    /// SDK wrapper in the public surface of the actor.
    let scp: SCP

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

    // MARK: - Initialization

    /// Creates a `Context` wrapping an existing UniFFI handle.
    ///
    /// This initializer is `internal` — production callers use
    /// ``create(scp:identity:params:)``.
    ///
    /// - Parameters:
    ///   - scp: The SDK-level ``SCP`` instance that minted the handle.
    ///     Every per-context UniFFI call dispatches through this reference.
    ///   - handle: The opaque UniFFI context handle.
    ///   - identity: The ``Identity`` of the local participant.
    ///   - contextId: Optional override for the context ID. When `nil`,
    ///     the ID is read from the handle. Pass explicitly in tests where
    ///     the handle has no backing FFI pointer.
    ///   - creatorDid: Optional override for the creator DID. When `nil`,
    ///     the value is read from the handle.
    ///   - initialState: Optional override for the initial state. When
    ///     `nil`, the state is read from the handle (defaulting to
    ///     ``ContextState/active`` if the handle throws).
    init(
        scp: SCP,
        handle: ContextHandle,
        identity: Identity,
        contextId: String? = nil,
        creatorDid: String? = nil,
        initialState: ContextState? = nil
    ) {
        self.scp = scp
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
            // UniFFI ContextHandleProtocol.state() throws, so use try? with a
            // fallback. The fallback is `.poisoned` (NOT `.active`): a handle
            // whose state cannot be read, or that reports an unrecognized
            // string, must never present as a live/usable context. Per ADR-049
            // §10 the authoritative crash/poison signal is the error code on
            // the next per-context operation; this cached getter is best-effort
            // and fails safe to a non-active state.
            state = Context.mapStateString((try? handle.state()) ?? "poisoned")
        }
    }

    /// Maps the FFI lifecycle-state string to ``ContextState``.
    ///
    /// An unrecognized or unreadable state fails safe to ``ContextState/poisoned``
    /// rather than ``ContextState/active``: per ADR-049 §10 the cached
    /// ``state`` getter is best-effort, and an unknown context must never be
    /// reported as live. The authoritative crash/poison signal is the
    /// `SCP-CTX-2134`/`2135` error code surfaced on the next per-context
    /// operation, not this getter.
    static func mapStateString(_ stateString: String) -> ContextState {
        switch stateString {
        case "creating": return .creating
        case "active": return .active
        case "closing": return .closing
        case "closed": return .closed
        case "expired": return .expired
        case "migrating_out": return .migratingOut
        case "tombstoned": return .tombstoned
        case "poisoned": return .poisoned
        default: return .poisoned
        }
    }

    // MARK: - deinit

    deinit {
        // Safety net: schedule close if the caller forgot to call it explicitly.
        // `try?` intentionally suppresses errors in the deinit path. The detached
        // task captures only the handle, identity, and scp (all Sendable) — it
        // does not capture `self`, which would be invalid in deinit.
        streamContinuation?.finish()
        guard !didClose else { return }
        let capturedHandle = handle
        let capturedIdentity = identity
        let capturedScp = scp
        Task.detached {
            try? await capturedScp.contextClose(handle: capturedHandle, identity: capturedIdentity)
        }
    }

    // MARK: - Factory

    /// Creates a new SCP context on the given ``SCP`` instance.
    ///
    /// This is the primary factory method for creating contexts. It mints
    /// a fresh ``ContextHandle`` on ``scp`` via ``SCP/contextCreate`` and
    /// wraps it in an actor that stores ``scp`` so every subsequent
    /// per-context UniFFI call routes through the same instance.
    ///
    /// - Parameters:
    ///   - scp: The SDK-level ``SCP`` instance that will own the minted
    ///     handle. Handles minted here are rejected by any other ``SCP``
    ///     via the per-instance handle-affinity check.
    ///   - identity: The ``Identity`` of the context creator. Provides the DID
    ///     and key material for MLS group formation.
    ///   - params: The ``ContextParams`` governing the new context (ceiling,
    ///     governance, memory scope, TTL, promotability, min protocol version).
    /// - Returns: A new `Context` in the ``ContextState/active`` state.
    /// - Throws: ``ScpError/Context(msg:code:)`` if context creation fails.
    public static func create(
        scp: SCP,
        identity: Identity,
        params: ContextParams,
        contextId: String? = nil,
        creatorDid: String? = nil,
        initialState: ContextState? = nil
    ) async throws -> Context {
        let handle = try await scp.contextCreate(identity: identity, params: params)
        return Context(
            scp: scp,
            handle: handle,
            identity: identity,
            contextId: contextId,
            creatorDid: creatorDid,
            initialState: initialState
        )
    }

    /// Joins an existing SCP context by processing a received MLS Welcome,
    /// standing the local (joiner) identity up as a send-capable participant
    /// (ADR-049 Phase 2J).
    ///
    /// The join-side counterpart of ``create(scp:identity:params:)``: it
    /// completes the reserve → Welcome → join handshake begun by
    /// ``SCP/reserveKeyPackage(identity:)``. Given the Welcome the creator
    /// minted for a previously-reserved `KeyPackage`, this installs the joined
    /// MLS group, derives the joiner's §9.10.4 routing pseudonym from its
    /// locally-custodied identity (never caller-supplied), registers a context
    /// handle, and returns an active ``Context``. Without it a Welcome-joined
    /// node can DECRYPT but cannot SEND. A non-custodied joiner hard-fails with
    /// `"SCP-IDENT-1054"` before the single-use `KeyPackage` is consumed.
    ///
    /// The canonical reserve → Welcome → join happy path:
    ///
    /// ```swift
    /// // 1. Joiner reserves a single-use KeyPackage under its own identity.
    /// let reservation = try await scp.reserveKeyPackage(identity: joiner)
    ///
    /// // 2. Hand `reservation.keyPackagePublic` to the creator out of band; the
    /// //    creator adds it to the MLS group and returns a Welcome addressed to it.
    /// let welcomeBytes: Data = /* received from the creator */
    ///
    /// // 3. Joiner processes the Welcome and stands up a send-capable context.
    /// let ctx = try await Context.joinFromWelcome(
    ///     scp: scp,
    ///     identity: joiner,
    ///     creatorDid: creator.did(),
    ///     contextId: contextId,
    ///     params: params,
    ///     reservationId: reservation.reservationId,
    ///     welcomeBytes: welcomeBytes
    /// )
    /// try await ctx.send(Data("hello from the joiner".utf8))
    /// ```
    ///
    /// - Parameters:
    ///   - scp: The SDK-level ``SCP`` instance that owns the reservation and
    ///     will own the minted handle. Must be the same instance that produced
    ///     the reservation via ``SCP/reserveKeyPackage(identity:)`` — a handle
    ///     minted here is rejected by any other ``SCP`` via the per-instance
    ///     handle-affinity check.
    ///   - identity: The LOCAL (joiner) ``Identity`` — the reservation holder.
    ///     Its custody derives the routing pseudonym, so it MUST be locally
    ///     custodied; passed separately from `creatorDid` so the two cannot be
    ///     transposed.
    ///   - creatorDid: DID of the context creator / admin that minted the
    ///     Welcome (from the legible params).
    ///   - contextId: The canonical id of the context being joined.
    ///   - params: The legible ``ContextParams`` — the SAME shape
    ///     ``create(scp:identity:params:)`` takes.
    ///   - reservationId: The ``ReservedKeyPackage/reservationId`` returned by
    ///     ``SCP/reserveKeyPackage(identity:)`` for the `KeyPackage` this Welcome
    ///     addresses.
    ///   - welcomeBytes: The TLS-serialized MLS Welcome message (`Data`, the
    ///     SDK's byte convention).
    /// - Returns: An active ``Context`` re-homed under the joiner's identity.
    /// - Throws: ``ScpError/Identity(msg:code:)`` (`"SCP-IDENT-1054"`) if the
    ///   joiner is not locally custodied; ``ScpError/Validation(msg:code:)`` if
    ///   the DIDs, context id, params, or reservation id are malformed; or
    ///   ``ScpError/Context(msg:code:)`` if the context id already collides on
    ///   this instance or the Welcome spawn fails (bad/duplicate/replayed
    ///   Welcome, first-writer-wins collision, or fail-closed persist failure).
    public static func joinFromWelcome(
        scp: SCP,
        identity: Identity,
        creatorDid: String,
        contextId: String,
        params: ContextParams,
        reservationId: String,
        welcomeBytes: Data
    ) async throws -> Context {
        let handle = try await scp.contextJoinFromWelcome(
            identity: identity,
            creatorDid: creatorDid,
            contextId: contextId,
            params: params,
            reservationId: reservationId,
            welcomeBytes: welcomeBytes
        )
        return Context(scp: scp, handle: handle, identity: identity)
    }

    // MARK: - Public methods

    /// Sends a message payload to this context.
    ///
    /// The payload is encrypted via MLS and delivered to all context members
    /// through the Rust protocol engine. Forwards to
    /// ``SCP/contextSend(handle:identity:payload:spendingUcanJwt:)`` on the
    /// actor's ``scp``.
    ///
    /// - Parameter payload: The raw message data to send.
    /// - Throws: ``ScpError/Context(msg:code:)``:
    ///   - `"SCP-CTX-2001"` if the context is not active.
    ///   - `"SCP-CTX-2095"` if this is a multi-member encrypted context and no
    ///     peer has announced its routing ID yet (§9.10.4). The send fails
    ///     closed and is rolled back — no charge, no event — and should be
    ///     retried once peers' pseudonym announcements have been delivered. A
    ///     lone-member send is a no-op; broadcast contexts are unaffected.
    ///   - or if the bridge send operation otherwise fails.
    public func send(_ payload: Data, spendingUcanJwt: String? = nil) async throws {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2001"
            )
        }
        try await scp.contextSend(
            handle: handle, identity: identity, payload: payload, spendingUcanJwt: spendingUcanJwt
        )
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
        try scp.setEconomicPolicy(handle: handle, policyJson: policyJson)
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
        return try scp.getEconomicPolicy(handle: handle)
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
            // Bridge subscription is async throws on the UniFFI side; drive it on
            // a detached task so the `messages` accessor itself does not need
            // to be async. Failures are surfaced through `lastError` via the
            // listener adapter.
            let capturedHandle = handle
            let capturedScp = scp
            let capturedError = streamError
            Task.detached {
                do {
                    try await capturedScp.contextSubscribe(handle: capturedHandle, listener: listener)
                } catch let scpError as ScpError {
                    capturedError.set(scpError)
                    continuation.finish()
                } catch {
                    capturedError.set(
                        ScpError.Context(
                            msg: "contextSubscribe failed: \(error.localizedDescription)",
                            code: "SCP-CTX-2004"
                        )
                    )
                    continuation.finish()
                }
            }
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
        try await scp.contextLeave(handle: handle, identity: identity)
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
        try await scp.contextClose(handle: handle, identity: identity)
        state = .closed
        didClose = true
        streamContinuation?.finish()
        streamContinuation = nil
    }

    /// Adds another identity to this context as a member.
    ///
    /// Forwards to ``SCP/contextJoin(handle:identity:spendingUcanJwt:)`` on
    /// the actor's ``scp``, which is the same instance that minted ``handle``
    /// — cross-instance calls are rejected by the handle-affinity check.
    ///
    /// - Parameters:
    ///   - identity: The ``Identity`` joining the context.
    ///   - spendingUcanJwt: Optional encoded UCAN JWT authorising the join
    ///     cost (spec §19, ADR-033). Forwarded to the manager for
    ///     AND-composition with any per-join economic policy.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not in
    ///   active state, or if the bridge join operation fails.
    public func join(
        _ identity: Identity,
        spendingUcanJwt: String? = nil
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2013"
            )
        }
        try await scp.contextJoin(
            handle: handle, identity: identity, spendingUcanJwt: spendingUcanJwt
        )
    }
}

// MARK: - Context Join (free function)

/// Joins an existing SCP context on the given ``SCP`` instance.
///
/// Forwards to ``SCP/contextJoin(handle:identity:spendingUcanJwt:)``. The
/// identity provides the key package for MLS group admission. The
/// ``ContextHandle`` must have been minted on the same ``SCP`` instance
/// — cross-instance calls are rejected by the handle-affinity check.
///
/// - Parameters:
///   - scp: The SDK-level ``SCP`` instance that owns ``handle``.
///   - handle: The ``ContextHandle`` for the context to join.
///   - identity: The ``Identity`` joining the context.
///   - spendingUcanJwt: Optional encoded UCAN JWT authorising the join cost
///     (spec §19, ADR-033).
/// - Throws: ``ScpError/Context(msg:code:)`` if the context is not
///   in active state or the join operation fails.
///
/// ## Provenance
///
/// - ADR-021 (UniFFI Bridge)
/// - ADR-026 (Swift SDK)
/// - ADR-048 (Multi-instance SCP) — handle-affinity enforcement
/// - Spec section 5 (Context Lifecycle)
public func joinContext(
    scp: SCP,
    handle: ContextHandle,
    identity: Identity,
    spendingUcanJwt: String? = nil
) async throws {
    try await scp.contextJoin(handle: handle, identity: identity, spendingUcanJwt: spendingUcanJwt)
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
///   - scp: The SDK-level ``SCP`` instance to dispatch through.
///   - paramsJson: JSON-serialized ``ContextParams`` from the invitation.
///   - inviterDid: DID string of the identity sending the invitation.
///   - identityDid: DID string of the local identity receiving the invitation.
///   - policyJson: Optional JSON-serialized ``AutoAcceptPolicy``. The
///     ``known_did`` allowlist (the sole auto-accept trigger, §5.12.2) travels
///     inside this policy's ``TrustRequirement.knownDid`` variant.
///   - spendingJson: Optional JSON-serialized ``SpendingContext``.
/// - Returns: An ``InvitationEvaluationResult`` with the pipeline decision.
/// - Throws: ``ScpError`` if evaluation fails.
public func evaluateContextInvitation(
    scp: SCP,
    paramsJson: String,
    inviterDid: String,
    identityDid: String,
    policyJson: String? = nil,
    spendingJson: String? = nil
) throws -> InvitationEvaluationResult {
    let decision = try scp.evaluateInvitation(
        paramsJson: paramsJson,
        inviterDid: inviterDid,
        identityDid: identityDid,
        policyJson: policyJson,
        spendingJson: spendingJson
    )
    return InvitationEvaluationResult(decision: decision)
}

// MARK: - MetadataRecord Inspection (§5.7.2, #615)

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
