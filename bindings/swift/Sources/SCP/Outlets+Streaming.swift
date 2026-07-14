import Foundation

// §5.4.5 Progressive Output (Streaming) — the SINGLE public `invoke` verb and
// the objects it returns (SCP-OUT-006 / SCP-OUT-038).
//
// This file mirrors the CANONICAL Python reference SDK
// (`bindings/python/scp_sdk/outlets.py`) exactly — the agent-first tenet
// requires an identical shape across all four bindings. The public surface is:
//
//   let handle = ctx.outlets.invoke(outletId:, input:, ucanToken:, …)
//        -> InvocationHandle          (NON-throwing, NON-async — opens LAZILY)
//   for try await chunk in handle { … }         // AsyncSequence of chunks
//   let result = try await handle.aggregate()    // the PRIMARY drain verb
//   try await handle.grantCredit(Credit(4))      // control plane
//   try await handle.cancel()                    // control plane
//
// The streaming FFI ops (`outletStreamOpen` / `outletStreamPollNext` /
// `outletStreamGrantCredit` / `outletStreamCancel`, exported by the UniFFI
// bridge crate `crates/scp-ffi/uniffi/src/outlet_stream.rs`) are wrapped BEHIND
// the handle — there is NO public `invokeStream` / `pollNext` free function
// (SCP-OUT-006).
//
// See `.docs/specs/05-contexts.md` §5.4.5, `.docs/prds/outlet.json`
// SCP-OUT-038, and the reference doc-comments in `outlets.py`.

// MARK: - JSONValue accessors for stream payloads

/// `JSONValue` (the decoded JSON value — the Swift analog of Python's `Any` /
/// TypeScript's `unknown`) is defined in `Trust.swift` and reused here for
/// outlet stream payloads and aggregate output. These accessors read the
/// variant fields the streaming surface needs.
public extension JSONValue {
    /// Object-member access — `nil` for a non-object or a missing key.
    subscript(_ key: String) -> JSONValue? {
        if case let .object(members) = self { return members[key] }
        return nil
    }

    /// The value as an `Int64` (coercing an integral `.double`), or `nil`.
    var intValue: Int64? {
        switch self {
        case let .integer(value): return value
        case let .double(value): return Int64(value)
        default: return nil
        }
    }

    /// The value as a `String`, or `nil` if it is not a JSON string.
    var stringValue: String? {
        if case let .string(value) = self { return value }
        return nil
    }

    /// The value as a `Bool`, or `nil` if it is not a JSON boolean.
    var boolValue: Bool? {
        if case let .bool(value) = self { return value }
        return nil
    }
}

// MARK: - OutletError — the SDK-surface protocol-class outlet errors

/// Protocol-class (§5.4.4 `OutletErrorClass::Protocol`) outlet-streaming errors
/// RAISED BY THE SDK layer itself.
///
/// These are distinct from the bridge-raised ``ScpError`` (UniFFI already throws
/// typed ``ScpError`` cases for data-plane / control-plane rejections, so the
/// streaming wrapper lets those propagate untranslated — mirroring the sibling
/// saga wrapper). ``OutletError`` covers only the conditions the SDK generates
/// locally: an invalid ``Credit``, a control call on an already-terminal stream,
/// and generic protocol-class violations (a concurrent second consumer, or a
/// stream that closed without an `End` chunk).
///
/// Mirrors the Python `ProtocolError` hierarchy: `InvalidGrant` and
/// `StreamAlreadyClosed` are protocol-class siblings. Swift enums are flat, so
/// the three conditions are cases at the SAME depth (the SCP-OUT-038 round-5
/// same-depth rule) — a single `catch OutletError` handles the whole protocol
/// class, exactly as `except ProtocolError` does in Python.
public enum OutletError: Error, Sendable, Equatable {
    /// A ``Credit`` grant outside the valid `u32` range (§5.4.5). The
    /// ``Credit`` initializer rejects `0`; the `UInt32` type rejects
    /// negative / `>= 2**32` values by construction.
    case invalidGrant(msg: String, code: String)

    /// A control-plane call (`grantCredit` / `cancel`) on a handle whose stream
    /// has already reached a terminal chunk (§5.4.5 InvocationHandle lifecycle
    /// guard).
    case streamAlreadyClosed(msg: String, code: String)

    /// A generic protocol-class condition: a second concurrent consumer on the
    /// single shared drain, a stream that closed without an `End` chunk, or a
    /// malformed chunk from the bridge.
    case protocolViolation(msg: String, code: String)
}

// MARK: - Credit — a validated non-zero u32 stream-credit grant (§5.4.5)

/// A validated, non-zero `u32` stream-credit grant (§5.4.5).
///
/// Construct with `try Credit(n)`. Because the FFI grant is a `UInt32`, the type
/// itself gives you the negative / `>= 2**32` rejection for free — the throwing
/// initializer only needs to reject `0`. (Python and TypeScript additionally
/// reject negatives / `>= 2**32` / non-integers because their integer types are
/// unbounded; Swift's `UInt32` makes those unrepresentable.)
///
/// ``InvocationHandle/grantCredit(_:)`` consumes a `Credit`, never a raw
/// `UInt32` — so a bare integer is a COMPILE error, forcing every grant through
/// the validating initializer.
///
/// ```swift
/// try await handle.grantCredit(Credit(4))
/// ```
public struct Credit: Sendable, Hashable {
    /// The validated grant magnitude (a non-zero `u32`). The canonical accessor
    /// across every SDK (superseding the earlier `.raw` sketch).
    public let value: UInt32

    /// Constructs a ``Credit``, rejecting `0`.
    ///
    /// - Throws: ``OutletError/invalidGrant(msg:code:)`` if `value` is `0`
    ///   (the SCP-OUT-031 round-6 uniform `InvalidGrant` rule).
    public init(_ value: UInt32) throws {
        guard value != 0 else {
            throw OutletError.invalidGrant(
                msg: "Credit must be a non-zero u32 grant (§5.4.5), got 0",
                code: "SCP-OUTLET-6100"
            )
        }
        self.value = value
    }
}

// MARK: - OutletStreamChunk — one decoded stream chunk (§5.4.5)

/// One chunk in an outlet stream (§5.4.5).
///
/// Yielded by iterating an ``InvocationHandle``. `Progress` chunks are surfaced
/// (not filtered), so a consumer sees the full `Data` / `Progress` / `End` /
/// `Error` sequence in order.
public struct OutletStreamChunk: Sendable, Equatable {
    /// Strictly monotonic per-stream sequence number, starting at `0`.
    public let sequence: UInt64

    /// Payload variant tag: `"data"`, `"progress"`, `"end"`, or `"error"`
    /// (the wire `@type`).
    public let kind: String

    /// The variant's fields, minus the `@type` tag. For `data`:
    /// `["value": …]`; `progress`: `["pct": …, "note": …]`; `end`:
    /// `["aggregate": …, "provenance": …, "execution_time_ms": …]`; `error`:
    /// `["code": …, "message": …, "terminal": …]`.
    public let payload: [String: JSONValue]

    /// Stream identifier as a lowercase hex string (opaque to the SDK).
    public let requestId: String

    /// Operator's per-chunk Ed25519 signature as a lowercase hex string
    /// (opaque to the SDK; verified runtime-side per §5.4.5).
    public let signature: String

    /// `true` for the chunk that closes the stream (`End`, or an `Error` with
    /// `terminal: true`).
    public var isTerminal: Bool {
        if kind == "end" { return true }
        if kind == "error" { return payload["terminal"]?.boolValue ?? false }
        return false
    }

    /// Builds the ``Aggregate`` from an `End` chunk payload (§5.4.5 `End`).
    func makeAggregate() -> Aggregate {
        let executionMs = payload["execution_time_ms"]?.intValue ?? 0
        return Aggregate(
            value: payload["aggregate"] ?? .null,
            provenance: payload["provenance"] ?? .object([:]),
            executionTimeMs: executionMs < 0 ? 0 : UInt64(executionMs)
        )
    }

    /// The `SCP-OUTLET-NNNN` code carried by an `Error` chunk.
    var errorCode: String {
        payload["code"]?.stringValue ?? "SCP-OUTLET-6000"
    }

    /// The human-readable message carried by an `Error` chunk.
    var errorMessage: String {
        payload["message"]?.stringValue ?? "outlet stream error"
    }

    /// Parses the JSON-serialized ``OutletStreamChunk`` returned by
    /// `outletStreamPollNext`.
    ///
    /// - Throws: ``OutletError/protocolViolation(msg:code:)`` if the bytes are
    ///   not a well-formed chunk (a bridge / transport invariant violation).
    static func parse(_ data: Data) throws -> OutletStreamChunk {
        let envelope: OutletStreamChunkEnvelope
        do {
            envelope = try JSONDecoder().decode(OutletStreamChunkEnvelope.self, from: data)
        } catch {
            throw OutletError.protocolViolation(
                msg: "malformed outlet stream chunk from bridge: \(error)",
                code: "SCP-OUTLET-6100"
            )
        }
        guard let typeTag = envelope.payload["@type"]?.stringValue else {
            throw OutletError.protocolViolation(
                msg: "malformed outlet stream chunk from bridge: missing payload/@type",
                code: "SCP-OUTLET-6100"
            )
        }
        var variant = envelope.payload
        variant.removeValue(forKey: "@type")
        return OutletStreamChunk(
            sequence: envelope.sequence ?? 0,
            kind: typeTag,
            payload: variant,
            requestId: outletStreamHexField(envelope.requestId),
            signature: outletStreamHexField(envelope.sig)
        )
    }
}

/// The JSON envelope `outletStreamPollNext` returns.
///
/// `request_id` / `sig` are `serde_bytes` fields — a JSON array of `u8` under
/// `serde_json`, or a hex string from a hardened bridge / fixture. Both are
/// rendered as a lowercase hex string so the SDK surface is stable.
private struct OutletStreamChunkEnvelope: Decodable {
    let sequence: UInt64?
    let requestId: JSONValue?
    let sig: JSONValue?
    let payload: [String: JSONValue]

    enum CodingKeys: String, CodingKey {
        case sequence
        case payload
        case requestId = "request_id"
        case sig
    }
}

/// Renders a bridge byte field (a JSON array of `u8`, or a hex string) as a
/// lowercase hex string.
private func outletStreamHexField(_ value: JSONValue?) -> String {
    switch value {
    case let .string(hex):
        return hex
    case let .array(elements):
        var bytes = [UInt8]()
        bytes.reserveCapacity(elements.count)
        for element in elements {
            if let byte = element.intValue { bytes.append(UInt8(byte & 0xFF)) }
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    default:
        return ""
    }
}

// MARK: - Aggregate — the aggregated terminal result (§5.4.5 End)

/// The aggregated terminal result of an outlet invocation (§5.4.5 `End`).
///
/// Returned by ``InvocationHandle/aggregate()``. Carries the full `End` chunk
/// payload: the aggregate output value (matching the outlet's
/// `aggregate_schema`, validated executor-side per §5.4.5), the provenance
/// record for the stream output, and the summed wall-clock execution time.
public struct Aggregate: Sendable, Equatable {
    /// Aggregate output value — the `End.aggregate` field (matches the outlet's
    /// `aggregate_schema`, or the last `Data` value when the outlet declares
    /// none, per §5.4.5).
    public let value: JSONValue

    /// Provenance metadata for the full stream output (§5.4.5 `End.provenance`).
    public let provenance: JSONValue

    /// Total wall-clock execution time in milliseconds, summed across the
    /// stream's lifetime.
    public let executionTimeMs: UInt64
}

// MARK: - OutletStreamNative — the narrow FFI streaming surface

/// The narrow UniFFI streaming surface the ``InvocationHandle`` drives.
///
/// The production conformer (``ContextStreamBridge``) forwards to the UniFFI
/// `Scp` object; tests inject a scripted mock replaying §5.4.5 wire chunks.
/// Open takes only the strings the handle knows — the ``ContextHandle`` is
/// captured by the concrete bridge, so a mock never needs to fabricate one.
protocol OutletStreamNative: Sendable {
    func openStream(
        outletId: String,
        inputJson: String,
        callerDid: String,
        ucanToken: String,
        proofTokens: [String]?,
        spendingUcan: String?,
        timeoutMs: UInt32?,
        estimatedChunkCount: UInt32?
    ) async throws -> String

    func pollNext(handleId: String) async throws -> Data?

    func grantCredit(handleId: String, callerDid: String, grant: UInt32) async throws

    func cancel(handleId: String, callerDid: String) async throws
}

/// Production ``OutletStreamNative`` — forwards to the UniFFI `Scp` object,
/// capturing the context-affine ``ContextHandle`` for `openStream`.
struct ContextStreamBridge: OutletStreamNative {
    let scp: SCP
    let handle: ContextHandle

    func openStream(
        outletId: String,
        inputJson: String,
        callerDid: String,
        ucanToken: String,
        proofTokens: [String]?,
        spendingUcan: String?,
        timeoutMs: UInt32?,
        estimatedChunkCount: UInt32?
    ) async throws -> String {
        try await scp.inner.outletStreamOpen(
            handle: handle,
            outletId: outletId,
            inputJson: inputJson,
            callerDid: callerDid,
            ucanToken: ucanToken,
            proofTokens: proofTokens,
            spendingUcan: spendingUcan,
            timeoutMs: timeoutMs,
            estimatedChunkCount: estimatedChunkCount
        )
    }

    func pollNext(handleId: String) async throws -> Data? {
        try await scp.inner.outletStreamPollNext(handleId: handleId)
    }

    func grantCredit(handleId: String, callerDid: String, grant: UInt32) async throws {
        try await scp.inner.outletStreamGrantCredit(handleId: handleId, callerDid: callerDid, grant: grant)
    }

    func cancel(handleId: String, callerDid: String) async throws {
        try await scp.inner.outletStreamCancel(handleId: handleId, callerDid: callerDid)
    }
}

/// The immutable `openStream` argument set, captured at ``Outlets/invoke`` and
/// replayed on the (lazy) first open.
struct OutletStreamOpenParams {
    let outletId: String
    let input: Data
    let callerDid: String
    let ucanToken: String
    let proofTokens: [String]?
    let spendingUcan: String?
    let timeoutMs: UInt32?
    let estimatedChunkCount: UInt32?

    /// Renders the captured `input` bytes as the UTF-8 JSON string the bridge
    /// consumes — deferred to open so a bad-UTF-8 input surfaces on the first
    /// await / iteration / grant, not from the non-throwing ``Outlets/invoke``.
    func inputJson() throws -> String {
        guard let json = String(data: input, encoding: .utf8) else {
            throw ScpError.Outlet(
                msg: "Outlet input is not valid UTF-8",
                code: "SCP-OUTLET-6001"
            )
        }
        return json
    }
}

// MARK: - InvocationHandle — the single object returned by invoke()

/// The single object returned by `ctx.outlets.invoke(...)` (SCP-OUT-038).
///
/// An ``InvocationHandle`` is simultaneously:
///
/// - An `AsyncSequence` — `for try await chunk in handle` yields each
///   ``OutletStreamChunk`` (`Data` and `Progress` included) up to and including
///   the terminal chunk.
/// - The home of the explicit ``aggregate()`` drain verb — `try await
///   handle.aggregate()` drains the stream to its terminal and returns the
///   ``Aggregate`` built from the `End` chunk. A terminal `Error` chunk throws a
///   typed ``ScpError/Outlet(msg:code:)`` carrying the chunk's `SCP-OUTLET-NNNN`
///   code. (Swift is NOT awaitable-for-aggregate — `aggregate()` is the sole
///   aggregate path, unlike Python/TS `await handle` sugar.)
///
/// **One shared drain, three directions.** Both surfaces consume the SAME
/// underlying stream and share one terminal-capture; the executor's chunk
/// sequence is drained exactly once:
///
/// 1. **iterate then aggregate** — after iteration runs to the terminal,
///    ``aggregate()`` returns the CACHED ``Aggregate`` (no re-drain).
/// 2. **aggregate then iterate** — after ``aggregate()``, subsequent iteration
///    yields NOTHING (the stream is already fully drained).
/// 3. **partial-iterate then aggregate** — ``aggregate()`` drains the REMAINING
///    chunks to the terminal and returns the executor's `End.aggregate`.
///
/// A stream has a single consumer: driving it from two tasks concurrently throws
/// ``OutletError/protocolViolation(msg:code:)`` on the second driver rather than
/// silently splitting the chunk sequence between them. The handle is an `actor`,
/// so the shared drain is serialized and the terminal cache is race-free.
///
/// The stream opens LAZILY — ``Outlets/invoke`` returns immediately without
/// blocking or throwing, and the `outletStreamOpen` FFI call happens on the
/// first iteration, ``aggregate()``, or ``grantCredit(_:)`` (a grant needs a
/// live stream). ``cancel()`` on a never-opened handle is a local no-op close —
/// it does NOT open the stream (no escrow reservation / admission slot) just to
/// cancel it. Open-time and mid-drain bridge rejections surface as the matching
/// typed ``ScpError`` on the first await / iteration / control call.
public actor InvocationHandle {
    private let bridge: any OutletStreamNative
    private let params: OutletStreamOpenParams

    /// Memoized bridge handle id, set once the stream is opened.
    private var handleId: String?
    /// Memoizes the in-flight open so concurrent first-touches (e.g. a
    /// `grantCredit` racing the first `next`) open only one stream.
    private var openTask: Task<String, Error>?
    /// Set once a terminal chunk (End / terminal Error) is observed, or the
    /// sender drops without a terminal. Gates the control-plane lifecycle.
    private var closed = false
    /// In-flight re-entrancy guard: `true` while a drain poll is outstanding, so
    /// a second concurrent driver fails loud instead of stealing chunks from the
    /// shared single-consumer drain.
    private var draining = false
    /// Captured terminal state, read back by ``aggregate()``.
    private var aggregateResult: Aggregate?
    private var terminalError: ScpError?

    init(bridge: any OutletStreamNative, params: OutletStreamOpenParams) {
        self.bridge = bridge
        self.params = params
    }

    // MARK: Lazy open

    /// Opens the stream exactly once (idempotent), returning the bridge handle
    /// id. Concurrent first-touches await the same open task.
    private func ensureOpen() async throws -> String {
        if let handleId { return handleId }
        if let openTask { return try await openTask.value }
        let bridge = self.bridge
        let params = self.params
        let task = Task<String, Error> {
            let inputJson = try params.inputJson()
            return try await bridge.openStream(
                outletId: params.outletId,
                inputJson: inputJson,
                callerDid: params.callerDid,
                ucanToken: params.ucanToken,
                proofTokens: params.proofTokens,
                spendingUcan: params.spendingUcan,
                timeoutMs: params.timeoutMs,
                estimatedChunkCount: params.estimatedChunkCount
            )
        }
        openTask = task
        do {
            let id = try await task.value
            handleId = id
            return id
        } catch {
            // Clear the memoized task so a later call can retry the open; the
            // rejection (UCAN denial, input-schema violation, escrow
            // InsufficientFunds/overflow) surfaces to this caller unchanged.
            openTask = nil
            throw error
        }
    }

    // MARK: Drain

    /// Drains one chunk from the shared single-consumer stream, or `nil` at the
    /// terminal. The concurrent-consumer guard and the terminal cache live here.
    func drainNext() async throws -> OutletStreamChunk? {
        if closed { return nil }
        if draining {
            throw OutletError.protocolViolation(
                msg: "InvocationHandle is already being drained by another consumer; "
                    + "an outlet stream has a single shared drain — do not iterate or "
                    + "aggregate it from two tasks concurrently",
                code: "SCP-OUTLET-6100"
            )
        }
        draining = true
        defer { draining = false }

        let id = try await ensureOpen()
        let raw = try await bridge.pollNext(handleId: id)
        guard let raw else {
            // Abnormal terminal: the sender dropped without a terminal chunk.
            closed = true
            return nil
        }
        let chunk = try OutletStreamChunk.parse(raw)
        if chunk.isTerminal {
            // Terminal chunk closes the stream. Capture the terminal state for
            // aggregate(), mark closed, then still return the terminal chunk so
            // an iterating consumer observes it (End / terminal Error count
            // toward the visible chunk sequence).
            closed = true
            switch chunk.kind {
            case "end":
                aggregateResult = chunk.makeAggregate()
            case "error":
                terminalError = ScpError.Outlet(msg: chunk.errorMessage, code: chunk.errorCode)
            default:
                break
            }
        }
        return chunk
    }

    /// Drains the stream to its terminal and returns the ``Aggregate``.
    ///
    /// Idempotent: if the stream has already been drained (by full iteration),
    /// the captured ``Aggregate`` is returned without re-draining. A terminal
    /// `Error` chunk throws the typed ``ScpError/Outlet(msg:code:)`` it carried;
    /// a stream that ends without an `End` chunk throws
    /// ``OutletError/protocolViolation(msg:code:)``.
    ///
    /// The returned `value` matches the outlet's `aggregate_schema`: conformance
    /// is enforced executor-side at `End` emission (§5.4.5), so the SDK surfaces
    /// the validated aggregate faithfully rather than re-running JSON-Schema
    /// validation the executor already performed.
    public func aggregate() async throws -> Aggregate {
        while !closed {
            _ = try await drainNext()
        }
        if let terminalError { throw terminalError }
        guard let aggregateResult else {
            throw OutletError.protocolViolation(
                msg: "outlet stream closed without an End chunk",
                code: "SCP-OUTLET-6100"
            )
        }
        return aggregateResult
    }

    // MARK: Control plane

    /// Grants `credit` additional billable chunks to the live stream (§5.4.5
    /// credit-based backpressure).
    ///
    /// `credit` is a validated ``Credit``, never a raw `UInt32`. The FFI bridge
    /// signs the `OutletStreamCredit` internally under the pinned invoker's
    /// custody key and auto-assigns the strictly-monotonic `monotonic_seq` — the
    /// SDK never touches the invoker key or a replay counter (ADR-006).
    ///
    /// Opens the stream first if it is not yet open (a grant needs a live
    /// stream).
    ///
    /// - Throws: ``OutletError/streamAlreadyClosed(msg:code:)`` if the stream
    ///   has already reached a terminal chunk; otherwise the bridge's typed
    ///   ``ScpError`` (e.g. `SCP-PERM-3001` for a non-invoker caller, or an
    ///   escrow `InsufficientFunds` / `EscrowOverflow`).
    public func grantCredit(_ credit: Credit) async throws {
        if closed {
            throw OutletError.streamAlreadyClosed(
                msg: "cannot grant credit: the outlet stream has already closed",
                code: "SCP-OUTLET-6100"
            )
        }
        let id = try await ensureOpen()
        try await bridge.grantCredit(handleId: id, callerDid: params.callerDid, grant: credit.value)
    }

    /// Requests cancellation of the live stream (§5.4.5 cancellation).
    ///
    /// The FFI bridge signs the `OutletCancel` internally under the pinned
    /// invoker's custody key at the runtime-derived cursor (the SDK never
    /// supplies a `next_seq`). The executor emits exactly one terminal
    /// cancel-ack chunk within `stream_cancel_ack_secs`.
    ///
    /// Cancelling a handle whose stream was never opened is a LOCAL no-op close:
    /// it marks the handle closed WITHOUT opening the stream, so a cancel never
    /// reserves escrow / an admission slot (and never surfaces an open-time
    /// rejection) just to tear the stream down.
    ///
    /// - Throws: ``OutletError/streamAlreadyClosed(msg:code:)`` if the stream
    ///   has already reached a terminal chunk; otherwise the bridge's typed
    ///   ``ScpError`` (e.g. `SCP-PERM-3001` for a non-invoker caller).
    public func cancel() async throws {
        if closed {
            throw OutletError.streamAlreadyClosed(
                msg: "cannot cancel: the outlet stream has already closed",
                code: "SCP-OUTLET-6100"
            )
        }
        guard let id = handleId else {
            // Never opened — cancel is a local close, not a bridge round-trip.
            closed = true
            return
        }
        try await bridge.cancel(handleId: id, callerDid: params.callerDid)
    }
}

// MARK: - AsyncSequence conformance

extension InvocationHandle: AsyncSequence {
    public typealias Element = OutletStreamChunk

    /// A single-consumer async iterator over the SHARED drain. Every iterator
    /// created from a handle drives the same underlying stream (there is no
    /// cold, re-executing sequence) — draining from two of them concurrently
    /// throws ``OutletError/protocolViolation(msg:code:)`` on the second driver.
    public struct AsyncIterator: AsyncIteratorProtocol {
        let handle: InvocationHandle

        public func next() async throws -> OutletStreamChunk? {
            try await handle.drainNext()
        }
    }

    public nonisolated func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(handle: self)
    }
}

// MARK: - Outlets — the ctx.outlets accessor

/// The `ctx.outlets` accessor — the home of the single ``invoke(outletId:input:ucanToken:callerDid:proofTokens:spendingUcan:timeoutMs:estimatedChunkCount:)``
/// verb.
///
/// Bound to one ``Context``: it carries the caller DID that context is scoped to
/// and dispatches to the context's owning UniFFI bridge. Obtain via
/// ``Context/outlets``, never construct directly.
public struct Outlets: Sendable {
    let bridge: any OutletStreamNative
    let defaultCallerDid: String

    /// Invokes `outletId` and returns its ``InvocationHandle``.
    ///
    /// This is the ONLY public invocation verb (SCP-OUT-006). The returned
    /// handle is an `AsyncSequence` of ``OutletStreamChunk`` AND exposes the
    /// explicit ``InvocationHandle/aggregate()`` drain verb; the streaming FFI
    /// ops are wrapped behind it. `invoke` itself performs no I/O and does NOT
    /// block or throw — the stream opens lazily on the first iteration /
    /// ``InvocationHandle/aggregate()`` / control-plane call, and open-time
    /// rejections surface THERE as typed errors.
    ///
    /// - Parameters:
    ///   - outletId: Registration id of the target outlet.
    ///   - input: JSON-serialized input bytes (validated against the outlet's
    ///     `input_schema` at open; a non-UTF-8 input surfaces
    ///     ``ScpError/Outlet(msg:code:)`` `SCP-OUTLET-6001` on the first drain).
    ///   - ucanToken: The invoker's authorizing UCAN (required).
    ///   - callerDid: The invoking DID. Defaults to the context's identity DID
    ///     when omitted; must equal the DID pinned as the stream invoker for the
    ///     control-plane methods to authorize.
    ///   - proofTokens: Optional UCAN delegation-chain proof tokens.
    ///   - spendingUcan: Optional spending-authorization UCAN for a paid
    ///     (Action) outlet.
    ///   - timeoutMs: Optional per-stream timeout in milliseconds.
    ///   - estimatedChunkCount: Optional invoker-declared upper bound on
    ///     billable chunks (feeds the §5.4.5 `caveats_binding`).
    /// - Returns: The lazily-opening ``InvocationHandle``.
    public func invoke(
        outletId: String,
        input: Data,
        ucanToken: String,
        callerDid: String? = nil,
        proofTokens: [String]? = nil,
        spendingUcan: String? = nil,
        timeoutMs: UInt32? = nil,
        estimatedChunkCount: UInt32? = nil
    ) -> InvocationHandle {
        let params = OutletStreamOpenParams(
            outletId: outletId,
            input: input,
            callerDid: callerDid ?? defaultCallerDid,
            ucanToken: ucanToken,
            proofTokens: proofTokens,
            spendingUcan: spendingUcan,
            timeoutMs: timeoutMs,
            estimatedChunkCount: estimatedChunkCount
        )
        return InvocationHandle(bridge: bridge, params: params)
    }
}

// MARK: - Context.outlets accessor

public extension Context {
    /// The single-verb streaming outlet accessor (§5.4.5, SCP-OUT-038).
    ///
    /// `nonisolated` so `ctx.outlets.invoke(...)` reads synchronously without
    /// `await` — matching the canonical contract where `invoke` is non-async
    /// and non-throwing. The accessor reads only the actor's immutable, Sendable
    /// stored properties (`scp`, `handle`, `identity`).
    ///
    /// ```swift
    /// let handle = ctx.outlets.invoke(
    ///     outletId: "recipe_search",
    ///     input: Data(#"{"q":"pasta"}"#.utf8),
    ///     ucanToken: token
    /// )
    /// for try await chunk in handle { … }
    /// let result = try await handle.aggregate()
    /// ```
    nonisolated var outlets: Outlets {
        Outlets(
            bridge: ContextStreamBridge(scp: scp, handle: handle),
            defaultCallerDid: identity.did()
        )
    }
}
