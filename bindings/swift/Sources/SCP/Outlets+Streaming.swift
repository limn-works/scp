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
        if case let .object(members) = self {
            return members[key]
        }
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
        if case let .string(value) = self {
            return value
        }
        return nil
    }

    /// The value as a `Bool`, or `nil` if it is not a JSON boolean.
    var boolValue: Bool? {
        if case let .bool(value) = self {
            return value
        }
        return nil
    }
}

// MARK: - OutletError — the SDK-surface protocol-class outlet errors

/// Outlet-streaming errors RAISED BY THE SDK layer itself.
///
/// These are distinct from the bridge-raised ``ScpError`` (UniFFI already throws
/// typed ``ScpError`` cases for data-plane / control-plane rejections, so the
/// streaming wrapper lets those propagate untranslated — mirroring the sibling
/// saga wrapper). ``OutletError`` covers only the conditions the SDK generates
/// locally: an invalid ``Credit``, a control call on an already-terminal stream,
/// generic protocol-class violations (a concurrent second consumer, or a stream
/// that closed without an `End` chunk), and a receiver-detected stream gap.
///
/// Three of the four cases are Protocol-class (§5.4.4
/// `OutletErrorClass::Protocol`, code `SCP-OUTLET-6100`), mirroring the Python
/// `ProtocolError` hierarchy: `InvalidGrant` and `StreamAlreadyClosed` are
/// protocol-class siblings. The fourth, ``streamGap(msg:code:)``, is an
/// Execution-class member (§5.4.4 `OutletErrorClass::Execution::StreamGap`, code
/// `SCP-OUTLET-6131`) — the SDK-drain receiver gap check (§5.4.5 "Ordering and
/// gaps"). Swift enums are flat, so all four conditions are cases at the SAME
/// depth (the SCP-OUT-038 round-5 same-depth rule); the Execution-class
/// `streamGap` is surfaced at the same enum depth as the protocol-class cases —
/// mirroring how Python/TS/Kotlin document surfacing this execution code under
/// the shared outlet-error base — so a single `catch OutletError` handles the
/// whole family, exactly as `except ProtocolError` (plus its `StreamGap`
/// sibling) does in Python.
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

    /// A gap (missing sequence) in the stream's chunk sequence (§5.4.5
    /// "Ordering and gaps", `OutletErrorClass::Execution::StreamGap`). Sequence
    /// values are strictly monotonic per `request_id`; the drain tracks the
    /// expected next sequence and, on any non-contiguous chunk, cancels the
    /// stream through the bridge and throws this — a defense-in-depth
    /// monotonicity check (a same-context stream never gaps over its lossless
    /// ordered channel). Carries the execution-class code `SCP-OUTLET-6131`.
    case streamGap(msg: String, code: String)
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
        if kind == "end" {
            return true
        }
        if kind == "error" {
            return payload["terminal"]?.boolValue ?? false
        }
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
            if let byte = element.intValue {
                bytes.append(UInt8(byte & 0xFF))
            }
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
    /// Captured ``OutletError/streamGap(msg:code:)`` terminal, re-thrown by a
    /// re-``aggregate()`` after a gap closed the drain.
    private var streamGapError: OutletError?
    /// §5.4.5 receiver-side monotonicity cursor: the sequence the NEXT chunk
    /// must carry. Strictly monotonic per `request_id`, starting at 0; a chunk
    /// whose sequence differs is a ``OutletError/streamGap(msg:code:)``
    /// (defense-in-depth — same-context streams never gap over their lossless
    /// ordered channel).
    private var expectedSequence: UInt64 = 0

    init(bridge: any OutletStreamNative, params: OutletStreamOpenParams) {
        self.bridge = bridge
        self.params = params
    }

    // MARK: Lazy open

    /// Opens the stream exactly once (idempotent), returning the bridge handle
    /// id. Concurrent first-touches await the same open task.
    private func ensureOpen() async throws -> String {
        if let handleId {
            return handleId
        }
        if let openTask {
            return try await openTask.value
        }
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
        if closed {
            return nil
        }
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
        if chunk.sequence != expectedSequence {
            // §5.4.5 "Ordering and gaps": a non-contiguous sequence (a hole, or
            // a regression) is a receiver-detected StreamGap. Mark the drain
            // terminal, cancel the stream through the SAME bridge path public
            // cancel() uses, and throw — WITHOUT returning the offending chunk.
            // The check spans all chunk kinds (Data/Progress/End/Error) since
            // sequences are strictly monotonic across them.
            closed = true
            let gap = OutletError.streamGap(
                msg: "outlet stream sequence gap: expected \(expectedSequence), "
                    + "got \(chunk.sequence) (§5.4.5)",
                code: "SCP-OUTLET-6131"
            )
            streamGapError = gap
            // Best-effort receiver cancel: the StreamGap is the reported
            // terminal, so a cancel-path failure must not mask it.
            try? await sendCancel(id)
            throw gap
        }
        expectedSequence += 1
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
        if let streamGapError {
            throw streamGapError
        }
        if let terminalError {
            throw terminalError
        }
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
        try await sendCancel(id)
    }

    /// Signs and sends an `OutletCancel` through the bridge (§5.4.5). The single
    /// bridge cancel round-trip shared by the public ``cancel()`` and the
    /// drain's ``OutletError/streamGap(msg:code:)`` teardown, so both cancel
    /// through the identical signed path.
    private func sendCancel(_ id: String) async throws {
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

// MARK: - Cross-context STREAMING saga (§5.4.5 / §6.2.4, SCP-OUT-047)

// The STREAMING sibling of the unary block-until-terminal
// ``Context/invokeOutletCrossContextSaga(targetContext:callerDid:outletRegistrationId:input:assertedNonceHex:timestampMs:chainDepth:ucanProofId:)``.
// Per the ADR-049 §3a streaming wait-model amendment, the streaming saga returns
// its chunk receiver PROMPTLY at the Commit-transition (the caller consumes
// chunks as produced) and reaches `Committed` ASYNCHRONOUSLY at seal-close — it
// MUST NOT block until the stream terminates (an LLM stream can exceed the unary
// saga's ~95s bound; the credit ceiling bounds chunk COUNT, not wall-clock). The
// UniFFI open (`outletStreamingSagaOpen`) returns a durable `sagaId` promptly,
// and the SDK drives the stream by polling `outletStreamingSagaPollNext(sagaId)`
// behind ``StreamingSagaHandle`` — modelled on the same-context
// ``InvocationHandle``, MINUS the live control plane (there is no cross-context
// grantCredit / cancel — §6.2.5 / SCP-OUT-046, cancel_ack_ceiling = u64::MAX).
//
// This mirrors the CANONICAL Python reference `StreamingSagaHandle`
// (`bindings/python/scp_sdk/outlets.py`) exactly. Runtime-level guarantees
// (billed-count / execute-exactly-once) are proven Rust-side and are NOT
// re-asserted at this SDK layer.

/// The narrow UniFFI cross-context streaming-saga surface the
/// ``StreamingSagaHandle`` drives.
///
/// The production conformer (``ContextSagaStreamBridge``) forwards to the UniFFI
/// `Scp` object, capturing the source + target ``ContextHandle`` (so a mock
/// never needs to fabricate one); tests inject a scripted mock replaying §5.4.5
/// wire chunks.
protocol StreamingSagaNative: Sendable {
    // swiftlint:disable:next function_parameter_count
    func openSaga(
        callerDid: String,
        outletRegistrationId: String,
        inputJson: String,
        assertedNonceHex: String,
        timestampMs: UInt64,
        chainDepth: UInt8,
        ucanToken: String,
        proofTokens: [String]?,
        ucanProofId: String?,
        timeoutMs: UInt32?,
        estimatedChunkCount: UInt32?
    ) async throws -> String

    func pollNext(sagaId: String) async throws -> Data?
}

/// Production ``StreamingSagaNative`` — forwards to the UniFFI `Scp` object,
/// capturing the co-resident source + target ``ContextHandle`` for `openSaga`.
struct ContextSagaStreamBridge: StreamingSagaNative {
    let scp: SCP
    let sourceHandle: ContextHandle
    let targetHandle: ContextHandle

    // swiftlint:disable:next function_parameter_count
    func openSaga(
        callerDid: String,
        outletRegistrationId: String,
        inputJson: String,
        assertedNonceHex: String,
        timestampMs: UInt64,
        chainDepth: UInt8,
        ucanToken: String,
        proofTokens: [String]?,
        ucanProofId: String?,
        timeoutMs: UInt32?,
        estimatedChunkCount: UInt32?
    ) async throws -> String {
        try await scp.outletStreamingSagaOpen(
            sourceHandle: sourceHandle,
            targetHandle: targetHandle,
            callerDid: callerDid,
            outletRegistrationId: outletRegistrationId,
            inputJson: inputJson,
            assertedNonceHex: assertedNonceHex,
            timestampMs: timestampMs,
            chainDepth: chainDepth,
            ucanToken: ucanToken,
            proofTokens: proofTokens,
            ucanProofId: ucanProofId,
            timeoutMs: timeoutMs,
            estimatedChunkCount: estimatedChunkCount
        )
    }

    func pollNext(sagaId: String) async throws -> Data? {
        try await scp.outletStreamingSagaPollNext(sagaId: sagaId)
    }
}

/// The immutable `openSaga` argument set, captured at
/// ``Context/invokeOutletCrossContextStreamingSaga(targetContext:callerDid:outletRegistrationId:input:assertedNonceHex:timestampMs:chainDepth:ucanToken:proofTokens:ucanProofId:timeoutMs:estimatedChunkCount:)``
/// and replayed on the (lazy) first open. Mirrors the FFI open param order.
struct StreamingSagaOpenParams {
    let callerDid: String
    let outletRegistrationId: String
    let input: Data
    let assertedNonceHex: String
    let timestampMs: UInt64
    let chainDepth: UInt8
    let ucanToken: String
    let proofTokens: [String]?
    let ucanProofId: String?
    let timeoutMs: UInt32?
    let estimatedChunkCount: UInt32?

    /// Renders the captured `input` bytes as the UTF-8 JSON string the bridge
    /// consumes — deferred to open so a bad-UTF-8 input surfaces on the first
    /// await / iteration, not from the non-throwing open method.
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

/// The async-sequence + drainable handle for a §6.2.4 cross-context STREAMING
/// saga (SCP-OUT-047).
///
/// Returned by
/// ``Context/invokeOutletCrossContextStreamingSaga(targetContext:callerDid:outletRegistrationId:input:assertedNonceHex:timestampMs:chainDepth:ucanToken:proofTokens:ucanProofId:timeoutMs:estimatedChunkCount:)``.
/// Modelled on the same-context ``InvocationHandle``, minus the live control
/// plane (there is no cross-context grantCredit / cancel — §6.2.5 / SCP-OUT-046).
/// It is simultaneously:
///
/// - An `AsyncSequence` — `for try await chunk in handle` opens the saga on the
///   first pull (`outletStreamingSagaOpen` returns the durable `sagaId` PROMPTLY
///   at the Commit-transition, NOT block-until-terminal), then yields each
///   ``OutletStreamChunk`` polled from `outletStreamingSagaPollNext(sagaId)` up to
///   and including the terminal. Iteration stops on a terminal-flagged chunk
///   (`End` / terminal `Error`) OR on `nil` (an abnormal sender-drop terminal).
/// - The home of the explicit ``aggregate()`` drain verb — drains to the terminal
///   and returns the ``Aggregate`` from the `End` chunk; a terminal `Error` chunk
///   throws the typed ``ScpError/Outlet(msg:code:)`` it carried.
///
/// The saga is opened LAZILY — the open method returns immediately without
/// starting the saga; the open (which drives the saga to the Commit-transition
/// and reserves escrow) happens on first iteration / ``aggregate()``. An open
/// rejection — the §6.2.4 caller-principal binding, a Prepare/Commit saga
/// terminal (surfaced as the generated ``ScpError`` saga case), or an input/UCAN
/// rejection — surfaces there, and the receiver is never handed out.
///
/// A stream has a single consumer: draining it from two tasks concurrently throws
/// ``OutletError/protocolViolation(msg:code:)`` on the second driver. The handle
/// is an `actor`, so the shared drain is serialized and the terminal cache is
/// race-free.
public actor StreamingSagaHandle {
    private let bridge: any StreamingSagaNative
    private let params: StreamingSagaOpenParams

    /// Memoized durable saga id, set once the saga is opened. Doubles as the
    /// poll key. `nil` until the (lazy) first open.
    private var sagaId: String?
    /// Memoizes the in-flight open so concurrent first-touches open only one saga.
    private var openTask: Task<String, Error>?
    /// Set once a terminal chunk (End / terminal Error) is observed, or the
    /// sender drops without a terminal.
    private var closed = false
    /// In-flight re-entrancy guard: `true` while a drain poll is outstanding.
    private var draining = false
    /// Captured terminal state, read back by ``aggregate()``.
    private var aggregateResult: Aggregate?
    private var terminalError: ScpError?
    /// Captured ``OutletError/streamGap(msg:code:)`` terminal, re-thrown by a
    /// re-``aggregate()`` after a gap closed the drain.
    private var streamGapError: OutletError?
    /// §5.4.5 receiver-side monotonicity cursor: the sequence the NEXT chunk must
    /// carry. The bridge forwards A's operator-signed chunks VERBATIM over a
    /// lossless ordered channel (no re-sequencing), so a non-contiguous sequence
    /// is a ``OutletError/streamGap(msg:code:)`` (defense-in-depth). There is no
    /// live cancel plane, so the gap is a purely local terminal — the SDK does
    /// NOT sign a receiver cancel (unlike the same-context handle).
    private var expectedSequence: UInt64 = 0

    init(bridge: any StreamingSagaNative, params: StreamingSagaOpenParams) {
        self.bridge = bridge
        self.params = params
    }

    /// The durable supervisor-minted saga id, available once the saga has been
    /// opened (after the first iteration / ``aggregate()``); `nil` before.
    public var currentSagaId: String? {
        sagaId
    }

    /// Opens the saga exactly once (idempotent), returning the durable saga id.
    private func ensureOpen() async throws -> String {
        if let sagaId {
            return sagaId
        }
        if let openTask {
            return try await openTask.value
        }
        let bridge = self.bridge
        let params = self.params
        let task = Task<String, Error> {
            let inputJson = try params.inputJson()
            return try await bridge.openSaga(
                callerDid: params.callerDid,
                outletRegistrationId: params.outletRegistrationId,
                inputJson: inputJson,
                assertedNonceHex: params.assertedNonceHex,
                timestampMs: params.timestampMs,
                chainDepth: params.chainDepth,
                ucanToken: params.ucanToken,
                proofTokens: params.proofTokens,
                ucanProofId: params.ucanProofId,
                timeoutMs: params.timeoutMs,
                estimatedChunkCount: params.estimatedChunkCount
            )
        }
        openTask = task
        do {
            let id = try await task.value
            sagaId = id
            return id
        } catch {
            // Clear the memoized task so a later call can retry the open; the
            // rejection (caller-principal binding, saga terminal, UCAN denial)
            // surfaces to this caller unchanged, and the receiver is never handed
            // out (`sagaId` stays nil).
            openTask = nil
            throw error
        }
    }

    /// Drains one chunk from the shared single-consumer stream, or `nil` at the
    /// terminal. The concurrent-consumer guard and the terminal cache live here.
    func drainNext() async throws -> OutletStreamChunk? {
        if closed {
            return nil
        }
        if draining {
            throw OutletError.protocolViolation(
                msg: "StreamingSagaHandle is already being drained by another consumer; a "
                    + "cross-context streaming saga has a single shared drain — do not iterate "
                    + "or aggregate it from two tasks concurrently",
                code: "SCP-OUTLET-6100"
            )
        }
        draining = true
        defer { draining = false }

        let id = try await ensureOpen()
        let raw = try await bridge.pollNext(sagaId: id)
        guard let raw else {
            // Abnormal terminal: the sender dropped without a terminal chunk.
            closed = true
            return nil
        }
        let chunk = try OutletStreamChunk.parse(raw)
        if chunk.sequence != expectedSequence {
            // §5.4.5 "Ordering and gaps": a non-contiguous sequence is a
            // receiver-detected StreamGap. There is NO live cross-context cancel
            // plane (§6.2.5 / SCP-OUT-046), so the gap is a purely local terminal
            // — mark closed and throw WITHOUT returning the offending chunk and
            // WITHOUT a bridge cancel round-trip.
            closed = true
            let gap = OutletError.streamGap(
                msg: "cross-context streaming-saga sequence gap: expected \(expectedSequence), "
                    + "got \(chunk.sequence) (§5.4.5)",
                code: "SCP-OUTLET-6131"
            )
            streamGapError = gap
            throw gap
        }
        expectedSequence += 1
        if chunk.isTerminal {
            // Terminal chunk closes the stream. Capture the terminal state for
            // aggregate(), mark closed, then still return the terminal chunk so
            // an iterating consumer observes it.
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

    /// Drains the saga stream to its terminal and returns the ``Aggregate``.
    ///
    /// Idempotent: if the stream has already been drained (by full iteration),
    /// the captured ``Aggregate`` is returned without re-draining. A terminal
    /// `Error` chunk throws the typed ``ScpError/Outlet(msg:code:)`` it carried;
    /// a stream that ends without an `End` chunk throws
    /// ``OutletError/protocolViolation(msg:code:)``.
    public func aggregate() async throws -> Aggregate {
        while !closed {
            _ = try await drainNext()
        }
        if let streamGapError {
            throw streamGapError
        }
        if let terminalError {
            throw terminalError
        }
        guard let aggregateResult else {
            throw OutletError.protocolViolation(
                msg: "cross-context streaming saga closed without an End chunk",
                code: "SCP-OUTLET-6100"
            )
        }
        return aggregateResult
    }
}

// MARK: - StreamingSagaHandle AsyncSequence conformance

extension StreamingSagaHandle: AsyncSequence {
    public typealias Element = OutletStreamChunk

    /// A single-consumer async iterator over the SHARED drain. Every iterator
    /// created from a handle drives the same underlying saga stream — draining
    /// from two concurrently throws ``OutletError/protocolViolation(msg:code:)``
    /// on the second driver.
    public struct AsyncIterator: AsyncIteratorProtocol {
        let handle: StreamingSagaHandle

        public func next() async throws -> OutletStreamChunk? {
            try await handle.drainNext()
        }
    }

    public nonisolated func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(handle: self)
    }
}

// MARK: - Context cross-context streaming-saga entry points

public extension Context {
    /// Opens the §5.4.5 / §6.2.4 cross-context STREAMING outlet-invocation saga
    /// (SCP-OUT-047) and returns its ``StreamingSagaHandle``.
    ///
    /// The STREAMING sibling of
    /// ``invokeOutletCrossContextSaga(targetContext:callerDid:outletRegistrationId:input:assertedNonceHex:timestampMs:chainDepth:ucanProofId:)``.
    /// Where the unary saga BLOCKS until `Committed` and returns the result
    /// inline, this returns its chunk receiver PROMPTLY at the Commit-transition
    /// and reaches `Committed` ASYNCHRONOUSLY at seal-close (ADR-049 §3a). The
    /// returned handle is an `AsyncSequence` of ``OutletStreamChunk`` and exposes
    /// the explicit ``StreamingSagaHandle/aggregate()`` drain verb; the streaming
    /// FFI ops are wrapped behind it. This method performs no I/O and does not
    /// block — the saga opens lazily on the first iteration / ``aggregate()``,
    /// where an open rejection (the §6.2.4 caller-principal binding, a saga
    /// terminal `ScpError`, or an input/UCAN rejection) surfaces.
    ///
    /// There is NO live control plane (grantCredit / cancel) for the
    /// cross-context saga stream — per §6.2.5 / SCP-OUT-046 the credit window is
    /// fixed at open via `estimatedChunkCount` (cancel_ack_ceiling = u64::MAX).
    ///
    /// The `chainDepth` (`UInt8`) and `timestampMs` (`UInt64`) parameters cannot
    /// encode an out-of-range or negative value, so no manual range validation is
    /// performed — Swift's type system enforces the bridge's `u8` / `u64`
    /// boundaries by construction.
    ///
    /// - Parameters:
    ///   - targetContext: The ``Context`` hosting the target outlet (the
    ///     executing / target side); its handle is the `targetHandle`. The
    ///     receiver's own handle is the `sourceHandle` — the explicit
    ///     argument labels prevent a silent caller/target handle-swap.
    ///   - callerDid: The invoking principal's DID (bound to the bridge principal).
    ///   - outletRegistrationId: The target outlet's registration id.
    ///   - input: The outlet input as serialized JSON data (a non-UTF-8 input
    ///     surfaces ``ScpError/Outlet(msg:code:)`` `SCP-OUTLET-6001` on the first
    ///     drain).
    ///   - assertedNonceHex: The caller-asserted freshness nonce (32 hex chars).
    ///   - timestampMs: The caller-asserted freshness timestamp (Unix ms).
    ///   - chainDepth: The caller-asserted inbound chain depth (0 for a direct
    ///     invocation).
    ///   - ucanToken: The invocation UCAN authorizing the outlet call.
    ///   - proofTokens: Optional UCAN delegation-chain proof tokens.
    ///   - ucanProofId: Optional id of the spending UCAN proof.
    ///   - timeoutMs: Optional per-stream timeout in milliseconds.
    ///   - estimatedChunkCount: Optional invoker-declared upper bound on billable
    ///     chunks — the fixed credit window.
    /// - Returns: The lazily-opening ``StreamingSagaHandle``.
    ///
    /// ## Provenance
    ///
    /// - Spec section 6.2.4 / §5.4.5, ADR-049 §3a (SCP-OUT-047)
    nonisolated func invokeOutletCrossContextStreamingSaga(
        targetContext: Context,
        callerDid: String,
        outletRegistrationId: String,
        input: Data,
        assertedNonceHex: String,
        timestampMs: UInt64,
        chainDepth: UInt8,
        ucanToken: String,
        proofTokens: [String]? = nil,
        ucanProofId: String? = nil,
        timeoutMs: UInt32? = nil,
        estimatedChunkCount: UInt32? = nil
    ) -> StreamingSagaHandle {
        let params = StreamingSagaOpenParams(
            callerDid: callerDid,
            outletRegistrationId: outletRegistrationId,
            input: input,
            assertedNonceHex: assertedNonceHex,
            timestampMs: timestampMs,
            chainDepth: chainDepth,
            ucanToken: ucanToken,
            proofTokens: proofTokens,
            ucanProofId: ucanProofId,
            timeoutMs: timeoutMs,
            estimatedChunkCount: estimatedChunkCount
        )
        return StreamingSagaHandle(
            bridge: ContextSagaStreamBridge(
                scp: scp,
                sourceHandle: handle,
                targetHandle: targetContext.handle
            ),
            params: params
        )
    }

    /// Drives the key-bearing crash-recovery truncated-close for a cross-context
    /// streaming saga (SCP-OUT-046 #136 AC7, SCP-OUT-047).
    ///
    /// On FFI reconnect this authenticates the caller, surfaces the target
    /// context's Active Signing Key (resolved per-call from custody, never
    /// envelope-asserted), and seals a witness-absent durable prefix to resolve
    /// the saga `Committed` — WITHOUT re-opening the stream or re-invoking the
    /// outlet executor.
    ///
    /// `callerDid` MUST be an identity hosted by this bridge instance (the §6.2.4
    /// channel-authenticated principal) AND the invoker pinned at open — recovery
    /// is money-moving, so a hosted-but-non-invoker caller is rejected with
    /// ``ScpError/Permission(msg:code:)`` (`SCP-PERM-3001`, the SAME invoker gate
    /// the same-context grant/cancel/terminate siblings enforce) BEFORE the
    /// signing key is resolved.
    ///
    /// - Parameters:
    ///   - sagaId: The durable supervisor-minted saga id to recover.
    ///   - callerDid: The invoker DID (channel-authenticated, invoker-pinned).
    /// - Throws: ``ScpError/Context(msg:code:)`` if `callerDid` is not hosted by
    ///   this instance or `sagaId` is unknown; ``ScpError/Permission(msg:code:)``
    ///   (`SCP-PERM-3001`) if `callerDid` is hosted but is not the pinned invoker;
    ///   a saga terminal ``ScpError`` (`SagaNeedsRepair`) if the seal cannot
    ///   complete.
    ///
    /// ## Provenance
    ///
    /// - Spec section 6.2.4 / §5.4.5, ADR-049 §3a (SCP-OUT-047)
    func recoverStreamingSagaTruncatedClose(sagaId: String, callerDid: String) async throws {
        try await scp.outletStreamingSagaRecoverTruncatedClose(sagaId: sagaId, callerDid: callerDid)
    }
}
