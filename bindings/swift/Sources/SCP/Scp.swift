import Foundation

// SCP — the SDK-level caller-owned bridge instance (ADR-048).
//
// Each `SCP` wraps an independent UniFFI `Scp` object (from the regenerated
// bindings), which owns its own `UniffiBridgeInstance` — registries,
// transport, context manager. Callers construct explicit instances for
// multi-identity apps and for parallel-safe tests; the free-function façade
// has been deleted in Phase 4 PR 4 (ADR-048 demolition) — callers must
// construct an `SCP` explicitly.
//
// Persistence: Phase 4 PR 3 wired the real `ContextPersistence` trait
// through UniFFI via `StorageConfig.sqlite(path:, key:)`. The
// ``SCP/withStorage(sqliteDir:key:)`` convenience constructor exposes
// that variant with Swift-native `URL` and `Data` types. Closes #1260
// and #1491; the Phase 4 auto-reconnect-on-resume transport fix closes
// #1678.

/// Caller-owned SCP instance — the preferred SDK entry point.
///
/// Storage selection is MANDATORY (spec §17.6): construct via
/// ``init(storage:)`` / ``withStorage(_:)`` — there is no zero-argument
/// `SCP()` initializer.
///
/// ```swift
/// let scp = try SCP(storage: .inMemory)          // explicit dev/test storage
/// try await scp.shutdown(timeout: 5.0)           // graceful shutdown
/// ```
///
/// Each `SCP` wraps an independent UniFFI `Scp` handle. Handles minted
/// by one instance are rejected by others via
/// `HandleAffinityError` at the FFI boundary.
///
/// `SCP` is `@unchecked Sendable` because its internal `Scp` handle is
/// `Arc`-shared on the Rust side, and the public API only exposes
/// reads (`instanceId`) and thread-safe lifecycle methods.
public final class SCP: @unchecked Sendable {
    /// The UniFFI-generated `Scp` opaque object. `internal` so other SDK
    /// files can dispatch through it without exposing the raw opaque type
    /// to consumers.
    let inner: Scp

    /// Wraps an already-existing UniFFI `Scp` handle. Internal — used by
    /// the `withStorage(_:)` factories so they can reuse the stored-handle
    /// path without leaking the opaque type.
    init(inner: Scp) {
        self.inner = inner
    }

    /// Constructs an `SCP` with an explicit storage configuration.
    ///
    /// Storage selection is MANDATORY (spec §17.6): this throwing
    /// initializer is the sole public way to construct an `SCP`. There is
    /// no zero-argument `SCP()` initializer — a missing storage selection
    /// is a compile error.
    ///
    /// Pass ``StorageConfig/inMemory`` for development/test or
    /// ``StorageConfig/sqlite(path:key:)`` for production; callers who want
    /// a Swift-native `URL` + `Data` surface over the SQLite variant should
    /// prefer ``SCP/withStorage(sqliteDir:key:)``.
    ///
    /// - Throws: ``ScpError`` if a durable backend cannot be opened
    ///   (FAIL CLOSED, spec §17.6).
    public init(storage: StorageConfig) throws {
        inner = try Scp.withStorage(config: storage)
    }

    /// Constructs an `SCP` with an explicit storage configuration.
    ///
    /// Convenience static factory over ``init(storage:)`` —
    /// ``StorageConfig/inMemory`` for development/test or
    /// ``StorageConfig/sqlite(path:key:)`` for production.
    public static func withStorage(_ config: StorageConfig) throws -> SCP {
        try SCP(inner: Scp.withStorage(config: config))
    }

    /// Constructs an `SCP` backed by a `SQLCipher`-encrypted database at
    /// `{sqliteDir}/scp.db`.
    ///
    /// Convenience façade over ``withStorage(_:)`` with the
    /// ``StorageConfig/sqlite(path:key:)`` variant. Accepts Swift-native
    /// `URL` and `Data` and forwards to the UniFFI-generated
    /// `Scp.withStorage(config:)` constructor.
    ///
    /// The raw key material is copied once to cross the UniFFI boundary as
    /// `Vec<u8>`. The Rust side zeroes its copy after `SQLCipher` has
    /// consumed it; callers should zero their own `key` copy after this
    /// call returns — Foundation's `Data` does not guarantee zeroization
    /// on deallocation.
    ///
    /// FAIL CLOSED (spec §17.6): if the underlying database cannot be opened
    /// (bad key, unreadable directory, corrupt file) the call throws rather
    /// than silently degrading to an in-memory instance.
    ///
    /// - Parameters:
    ///   - sqliteDir: Directory the `scp.db` file lives in. The path is
    ///     passed through `std::path::PathBuf` on the Rust side, so
    ///     percent-encoded / non-UTF-8 paths must be converted before
    ///     calling.
    ///   - key: Raw encryption key material. Typically 32 bytes
    ///     (`SQLCipher` derives the final key via PBKDF2). Callers should
    ///     zero their copy after this call returns.
    /// - Returns: A fresh `SCP` wrapping a persistent bridge instance.
    /// - Throws: ``ScpError/context`` if the database cannot be opened.
    public static func withStorage(sqliteDir: URL, key: Data) throws -> SCP {
        try SCP(
            inner: Scp.withStorage(
                config: .sqlite(path: sqliteDir.path, key: .raw(key: key))
            )
        )
    }

    /// Constructs an `SCP` backed by a `SQLCipher`-encrypted database at
    /// `{sqliteDir}/scp.db`, with the encryption key derived from a
    /// passphrase via Argon2id (spec §17.6).
    ///
    /// Convenience façade over ``withStorage(_:)`` with the
    /// ``StorageConfig/sqlite(path:key:)`` variant carrying
    /// ``SqliteKeyMaterial/passphrase(passphrase:)``. The passphrase derives
    /// the same `SQLCipher` key on every open via a per-database salt sidecar
    /// (`{sqliteDir}/scp.salt`), so the same passphrase re-opens the same
    /// database across restarts.
    ///
    /// The passphrase crosses the UniFFI boundary as a `String`; the Rust
    /// side moves it into zeroizing memory before deriving the key. Callers
    /// should not retain the passphrase longer than necessary.
    ///
    /// - Parameters:
    ///   - sqliteDir: Directory the `scp.db` (and `scp.salt`) files live in.
    ///   - passphrase: Human-chosen passphrase. Mutually exclusive with the
    ///     raw-key path — the ``SqliteKeyMaterial`` sum type enforces this.
    /// - Returns: A fresh `SCP` wrapping a persistent bridge instance.
    /// - Throws: ``ScpError/context`` if the database cannot be opened (bad
    ///   passphrase against an existing DB, permission denied, corrupt file,
    ///   or a salt-sidecar fail-closed condition). FAIL CLOSED (spec §17.6):
    ///   the bridge never silently degrades to in-memory on a failed open.
    public static func withStorage(sqliteDir: URL, passphrase: String) throws -> SCP {
        try SCP(
            inner: Scp.withStorage(
                config: .sqlite(
                    path: sqliteDir.path,
                    key: .passphrase(passphrase: passphrase)
                )
            )
        )
    }

    /// The monotonic identifier for this bridge instance, unique per
    /// process. Used by the FFI handle-affinity check.
    public var instanceId: UInt64 {
        inner.instanceId()
    }

    /// Suspends this bridge instance (mobile/desktop backgrounding).
    ///
    /// Disconnects the transport and flushes context snapshots.
    /// Transport-dependent operations fail until ``resume()`` is called.
    ///
    /// - Throws: ``ScpError/transport`` if the transport lock is poisoned.
    public func suspend() throws {
        try inner.suspend()
    }

    /// Resumes a suspended bridge instance.
    ///
    /// Clears the suspended flag, then performs any per-bridge async work
    /// chained by the UniFFI `BridgeInstanceCore::resume` override:
    ///
    /// - Reconnects every relay URL captured in the pending-URL set at
    ///   suspend time (see #1678).
    /// - Rehydrates any persisted contexts written by the PR 3 SQLite
    ///   persistence path (see #1260 / #1491).
    ///
    /// The method is `async throws` because the underlying Rust
    /// `Scp::resume` is `pub async fn`; UniFFI generates a Swift
    /// `async throws` method that awaits the Rust future on the shared
    /// tokio runtime.
    ///
    /// - Throws: ``ScpError/context`` if the instance has been permanently
    ///   shut down, or ``ScpError/transport`` if a pending relay URL
    ///   could not be reconnected.
    public func resume() async throws {
        try await inner.resume()
    }

    /// Shuts down this instance with a graceful deadline (seconds).
    ///
    /// Awaits in-flight tasks up to `timeout` seconds, aborts any
    /// remaining tasks, then runs typed-field cleanup. Permanent. A
    /// second call is a no-op.
    ///
    /// Fractional seconds (e.g. `0.25`) are preserved to millisecond
    /// resolution before crossing the UniFFI boundary — the native
    /// side takes a `u64` millisecond count.
    ///
    /// `timeout` is clamped defensively:
    /// - `NaN` or values `<= 0` → `0` (abort in-flight tasks immediately).
    /// - `.infinity` or values that would overflow `UInt64` milliseconds
    ///   → `UInt64.max` (effectively unbounded).
    /// - Finite values in range → rounded to the nearest millisecond.
    ///
    /// - Parameter timeout: Maximum wall-clock duration to wait for
    ///   in-flight tasks, expressed as a ``Foundation/TimeInterval``
    ///   (`Double` seconds). Defaults to `5.0`.
    public func shutdown(timeout: TimeInterval = 5.0) async throws {
        let millis: UInt64 = if timeout.isNaN || timeout <= 0 {
            0
        } else if timeout.isInfinite || timeout >= Double(UInt64.max) / 1000.0 {
            // `>=` (not `>`): `Double(UInt64.max) == 2^64` due to IEEE-754
            // rounding (`Double` has 53 bits of mantissa, `UInt64` has 64),
            // so any `timeout` that is *exactly* the rounded boundary lands
            // on the "cast would overflow" side of `UInt64(x)`. A strict
            // `>` would miss that single exact value and trap in the
            // fallthrough cast. Clamping to `UInt64.max` there is correct
            // and bounded.
            UInt64.max
        } else {
            UInt64((timeout * 1000).rounded())
        }
        try await inner.shutdown(timeoutMillis: millis)
    }

    /// Shuts down this instance with a graceful deadline (milliseconds).
    ///
    /// Millisecond-granularity overload; forwards directly to the UniFFI
    /// `Scp.shutdown(timeoutMillis:)` method. Prefer this variant in
    /// tests and fixtures that want an exact millisecond deadline.
    public func shutdown(timeoutMillis: UInt64) async throws {
        try await inner.shutdown(timeoutMillis: millisClamp(timeoutMillis))
    }

    @inline(__always)
    private func millisClamp(_ value: UInt64) -> UInt64 {
        value
    }
}

// MARK: - Bridge method forwarding (ADR-048 PR 4 — demolition Phase C)

// Every UniFFI `Scp` method is forwarded through the `inner` handle so
// that callers write `scp.identityCreate(...)` as an idiomatic Swift
// method call. No state is shared with any other `SCP` instance.

/// Module-scope forwarder to the generated free `broadcastOpenKey` UniFFI
/// function. At module scope no instance/extension method shadows the global
/// name, so this bare call binds to the real binding (not a recursive
/// self-call). The SCP wrapper type's `broadcastOpenKey` method delegates here.
private func ffiBroadcastOpenKey(sealedJson: String, wrappingSecret: Data) throws -> Data {
    try broadcastOpenKey(sealedJson: sealedJson, wrappingSecret: wrappingSecret)
}

public extension SCP {
    /// Forwards to ``Scp/accessKeyGenerate`` on ``inner``.
    func accessKeyGenerate(contextId: String, memberDid: String, callerDid: String) async throws {
        try await inner.accessKeyGenerate(contextId: contextId, memberDid: memberDid, callerDid: callerDid)
    }

    /// Forwards to ``Scp/accessKeyRestore`` on ``inner``.
    func accessKeyRestore(contextId: String, memberDid: String, callerDid: String) async throws {
        try await inner.accessKeyRestore(contextId: contextId, memberDid: memberDid, callerDid: callerDid)
    }

    /// Forwards to ``Scp/accessKeyRevoke`` on ``inner``.
    func accessKeyRevoke(contextId: String, memberDid: String, callerDid: String) async throws {
        try await inner.accessKeyRevoke(contextId: contextId, memberDid: memberDid, callerDid: callerDid)
    }

    /// Forwards to ``Scp/addCheckpointCosignature`` on ``inner``.
    func addCheckpointCosignature(handle: ContextHandle, checkpointJson: String, signerDid: String, signatureHex: String) async throws -> String {
        try await inner.addCheckpointCosignature(handle: handle, checkpointJson: checkpointJson, signerDid: signerDid, signatureHex: signatureHex)
    }

    /// Forwards to ``Scp/addressResolve`` on ``inner``.
    func addressResolve(ownerDid: String, address: String, knownContextsJson: String?) throws -> String {
        try inner.addressResolve(ownerDid: ownerDid, address: address, knownContextsJson: knownContextsJson)
    }

    // swiftlint:disable function_parameter_count
    /// Forwards to ``Scp/aggregateTrustInput`` on ``inner``.
    func aggregateTrustInput(contextId: String, subjectDid: String, eventsJson: String, merkleRootJson: String, consequenceRulesJson: String, thresholdRequirementsJson: String, attestorSetsJson: String, cachedAttestationsJson: String, challengeResultsJson: String) throws -> String {
        try inner.aggregateTrustInput(contextId: contextId, subjectDid: subjectDid, eventsJson: eventsJson, merkleRootJson: merkleRootJson, consequenceRulesJson: consequenceRulesJson, thresholdRequirementsJson: thresholdRequirementsJson, attestorSetsJson: attestorSetsJson, cachedAttestationsJson: cachedAttestationsJson, challengeResultsJson: challengeResultsJson)
    }

    // swiftlint:enable function_parameter_count

    /// Forwards to ``Scp/applyPendingCeilingModification`` on ``inner``.
    func applyPendingCeilingModification(handle: ContextHandle, currentTimestamp: UInt64) async throws -> Bool {
        try await inner.applyPendingCeilingModification(handle: handle, currentTimestamp: currentTimestamp)
    }

    // `bridgeEvaluateTrust` moved to a UniFFI-generated free top-level
    // function under ADR-048 §1 + §7 Swift bullet. Call it directly:
    // `try bridgeEvaluateTrust(isBridged:isNativeTransport:shadowStatus:)`.

    /// Forwards to ``Scp/broadcastAdmission`` on ``inner``.
    func broadcastAdmission(handle: ContextHandle) async -> String? {
        await inner.broadcastAdmission(handle: handle)
    }

    /// Forwards to ``Scp/broadcastBlockSubscriber`` on ``inner``.
    func broadcastBlockSubscriber(handle: ContextHandle, subscriberDid: String, blockerDid: String) async throws {
        try await inner.broadcastBlockSubscriber(handle: handle, subscriberDid: subscriberDid, blockerDid: blockerDid)
    }

    /// Forwards to ``Scp/broadcastHandleKeyRequest`` on ``inner``.
    func broadcastHandleKeyRequest(handle: ContextHandle, authorDid: String, requesterDid: String, wrappingPubkey: Data) async throws -> String? {
        try await inner.broadcastHandleKeyRequest(handle: handle, authorDid: authorDid, requesterDid: requesterDid, wrappingPubkey: wrappingPubkey)
    }

    /// Forwards to the free ``broadcastOpenKey`` UniFFI binding.
    ///
    /// Opens an HPKE-sealed broadcast key (§5.14.2) using the subscriber's
    /// 32-byte X25519 ``wrappingSecret``, returning the raw 32-byte AES-256
    /// broadcast key. ``sealedJson`` is the JSON returned by
    /// ``broadcastHandleKeyRequest`` on grant.
    func broadcastOpenKey(sealedJson: String, wrappingSecret: Data) throws -> Data {
        // Routes through the module-scope forwarder because the generated
        // `broadcastOpenKey` is a free function whose name the SCP module shares
        // with this wrapper type — an in-method bare call would self-recurse.
        try ffiBroadcastOpenKey(sealedJson: sealedJson, wrappingSecret: wrappingSecret)
    }

    /// Forwards to ``Scp/broadcastIsSubscriber`` on ``inner``.
    func broadcastIsSubscriber(handle: ContextHandle, did: String) async -> Bool {
        await inner.broadcastIsSubscriber(handle: handle, did: did)
    }

    /// Forwards to ``Scp/broadcastPublish`` on ``inner``.
    func broadcastPublish(handle: ContextHandle, identity: Identity, payload: Data) async throws {
        try await inner.broadcastPublish(handle: handle, identity: identity, payload: payload)
    }

    /// Forwards to ``Scp/broadcastPublishAsset`` on ``inner``.
    func broadcastPublishAsset(handle: ContextHandle, identity: Identity, asset: AssetEntry, deployId: String?) async throws -> PublishResult {
        try await inner.broadcastPublishAsset(handle: handle, identity: identity, asset: asset, deployId: deployId)
    }

    /// Forwards to ``Scp/broadcastPublishAssets`` on ``inner``.
    func broadcastPublishAssets(handle: ContextHandle, identity: Identity, assets: [AssetEntry], deployId: String?) async throws -> BatchPublishResult {
        try await inner.broadcastPublishAssets(handle: handle, identity: identity, assets: assets, deployId: deployId)
    }

    /// Forwards to ``Scp/broadcastSubscribe`` on ``inner``.
    func broadcastSubscribe(handle: ContextHandle, subscriberDid: String) async throws {
        try await inner.broadcastSubscribe(handle: handle, subscriberDid: subscriberDid)
    }

    /// Forwards to ``Scp/broadcastSubscriberCount`` on ``inner``.
    func broadcastSubscriberCount(handle: ContextHandle) async -> UInt64? {
        await inner.broadcastSubscriberCount(handle: handle)
    }

    /// Forwards to ``Scp/broadcastUnblockSubscriber`` on ``inner``.
    func broadcastUnblockSubscriber(handle: ContextHandle, subscriberDid: String, unblockerDid: String) async throws {
        try await inner.broadcastUnblockSubscriber(handle: handle, subscriberDid: subscriberDid, unblockerDid: unblockerDid)
    }

    /// Forwards to ``Scp/broadcastUnsubscribe`` on ``inner``.
    func broadcastUnsubscribe(handle: ContextHandle, subscriberDid: String, rotateKeys: Bool) async throws {
        try await inner.broadcastUnsubscribe(handle: handle, subscriberDid: subscriberDid, rotateKeys: rotateKeys)
    }

    /// Forwards to ``Scp/configureLocalTransport`` on ``inner``.
    func configureLocalTransport(localDid: String) throws {
        try inner.configureLocalTransport(localDid: localDid)
    }

    /// Forwards to ``Scp/configureRelayTransport`` on ``inner``.
    func configureRelayTransport(relayUrl: String, localDid: String) async throws {
        try await inner.configureRelayTransport(relayUrl: relayUrl, localDid: localDid)
    }

    /// Forwards to ``Scp/contextClose`` on ``inner``.
    func contextClose(handle: ContextHandle, identity: Identity) async throws {
        try await inner.contextClose(handle: handle, identity: identity)
    }

    /// Forwards to ``Scp/contextCreate`` on ``inner``.
    func contextCreate(identity: Identity, params: ContextParams) async throws -> ContextHandle {
        try await inner.contextCreate(identity: identity, params: params)
    }

    /// Forwards to ``Scp/contextDrainEvents`` on ``inner``.
    func contextDrainEvents(handle: ContextHandle) async -> [String] {
        await inner.contextDrainEvents(handle: handle)
    }

    /// Forwards to ``Scp/contextExport`` on ``inner``.
    func contextExport(handle: ContextHandle) async throws -> Data {
        try await inner.contextExport(handle: handle)
    }

    /// Forwards to ``Scp/contextHandleTtlExpiry`` on ``inner``.
    func contextHandleTtlExpiry(handle: ContextHandle) async throws {
        try await inner.contextHandleTtlExpiry(handle: handle)
    }

    /// Forwards to ``Scp/contextImport`` on ``inner``.
    ///
    /// `importerIdentity` supplies the §9.10.4 per-context pseudonym
    /// derivation material so the importing member routes under its OWN routing
    /// ID rather than inheriting the exporter's local-instance pseudonym.
    func contextImport(data: Data, importerIdentity: Identity) async throws -> String {
        try await inner.contextImport(data: data, importerIdentity: importerIdentity)
    }

    /// Forwards to ``Scp/contextIsMember`` on ``inner``.
    func contextIsMember(handle: ContextHandle, did: String) async -> Bool {
        await inner.contextIsMember(handle: handle, did: did)
    }

    /// Forwards to ``Scp/contextJoin`` on ``inner``.
    func contextJoin(handle: ContextHandle, identity: Identity, spendingUcanJwt: String?) async throws {
        try await inner.contextJoin(handle: handle, identity: identity, spendingUcanJwt: spendingUcanJwt)
    }

    /// Forwards to ``Scp/contextLeave`` on ``inner``.
    func contextLeave(handle: ContextHandle, identity: Identity) async throws {
        try await inner.contextLeave(handle: handle, identity: identity)
    }

    /// Forwards to ``Scp/contextMemberCount`` on ``inner``.
    func contextMemberCount(handle: ContextHandle) async -> UInt64? {
        await inner.contextMemberCount(handle: handle)
    }

    /// Forwards to ``Scp/contextMemberDids`` on ``inner``.
    func contextMemberDids(handle: ContextHandle) async -> [String] {
        await inner.contextMemberDids(handle: handle)
    }

    /// Forwards to ``Scp/contextMemberRole`` on ``inner``.
    func contextMemberRole(handle: ContextHandle, did: String) async -> String? {
        await inner.contextMemberRole(handle: handle, did: did)
    }

    /// Forwards to ``Scp/contextProposeTtlExtension`` on ``inner``.
    func contextProposeTtlExtension(handle: ContextHandle, memberDid: String, proposedSeconds: UInt64) async throws -> Bool {
        try await inner.contextProposeTtlExtension(handle: handle, memberDid: memberDid, proposedSeconds: proposedSeconds)
    }

    /// Forwards to ``Scp/contextResetTtlTimer`` on ``inner``.
    func contextResetTtlTimer(handle: ContextHandle, newSeconds: UInt64) async {
        await inner.contextResetTtlTimer(handle: handle, newSeconds: newSeconds)
    }

    /// Forwards to ``Scp/contextSend`` on ``inner``.
    func contextSend(handle: ContextHandle, identity: Identity, payload: Data, spendingUcanJwt: String?) async throws {
        try await inner.contextSend(handle: handle, identity: identity, payload: payload, spendingUcanJwt: spendingUcanJwt)
    }

    /// Reconnects `identity`'s contexts after an offline period, running the
    /// ADR-029 six-phase reconnection protocol for each of `contextIds`
    /// flagged `needsReconnect` (§23.11).
    ///
    /// The driver lives at the FFI relay-client layer (ADR-029
    /// reconnection-driver addendum): it pulls relay-buffered messages via the
    /// `TransportManager` and reaches actor-owned reconnection state through
    /// the `Supervisor`. On success each context's `needsReconnect` flag is
    /// cleared. `lastRelayContacts` maps context id to last-relay-contact Unix
    /// seconds (tier classification); absent contexts default to the most
    /// conservative tier. Forwards to ``Scp/contextReconnect`` on ``inner``.
    ///
    /// Catch-up integrity (§9.9.3, §23.7): equivocation where a peer reports
    /// the **same** event count with a **different** Merkle root IS detected
    /// and surfaced (`ReconnectReport.contexts[].equivocationsDetected`).
    /// However, reconnection catch-up does NOT yet verify suffix integrity —
    /// the Merkle consistency proof confirming that fetched events genuinely
    /// extend this member's own history is specified separately. An
    /// equivocating relay that keeps a member perpetually *behind* (never
    /// reaching equal count) is therefore not yet detected on the catch-up
    /// path.
    func reconnect(identity: Identity, contextIds: [String], lastRelayContacts: [String: UInt64] = [:]) async throws -> ReconnectReport {
        try await inner.contextReconnect(identity: identity, contextIds: contextIds, lastRelayContacts: lastRelayContacts)
    }

    /// Forwards to ``Scp/contextSubscribe`` on ``inner``.
    func contextSubscribe(handle: ContextHandle, listener: MessageListener) async throws {
        try await inner.contextSubscribe(handle: handle, listener: listener)
    }

    /// Forwards to ``Scp/createGovernanceCheckpoint`` on ``inner``.
    func createGovernanceCheckpoint(handle: ContextHandle, checkpointSeq: UInt64, merkleRootHex: String, eventCount: UInt64, lastEventHashHex: String, stateSnapshotHashHex: String, creatorDid: String, creatorSignatureHex: String) async throws -> String {
        try await inner.createGovernanceCheckpoint(handle: handle, checkpointSeq: checkpointSeq, merkleRootHex: merkleRootHex, eventCount: eventCount, lastEventHashHex: lastEventHashHex, stateSnapshotHashHex: stateSnapshotHashHex, creatorDid: creatorDid, creatorSignatureHex: creatorSignatureHex)
    }

    /// Forwards to ``Scp/economyAntispamEscalatedCost`` on ``inner``.
    func economyAntispamEscalatedCost(contextId: String, senderDid: String, now: UInt64, baseCost: UInt64, thresholdsJson: String, floor: UInt64?, cap: UInt64?) throws -> UInt64 {
        try inner.economyAntispamEscalatedCost(contextId: contextId, senderDid: senderDid, now: now, baseCost: baseCost, thresholdsJson: thresholdsJson, floor: floor, cap: cap)
    }

    /// Forwards to ``Scp/economyAntispamRecord`` on ``inner``.
    func economyAntispamRecord(contextId: String, senderDid: String, timestamp: UInt64) throws {
        try inner.economyAntispamRecord(contextId: contextId, senderDid: senderDid, timestamp: timestamp)
    }

    /// Forwards to ``Scp/economyAntispamVelocity`` on ``inner``.
    func economyAntispamVelocity(contextId: String, senderDid: String, now: UInt64) throws -> UInt64 {
        try inner.economyAntispamVelocity(contextId: contextId, senderDid: senderDid, now: now)
    }

    /// Forwards to ``Scp/economyBudgetGrant`` on ``inner``.
    func economyBudgetGrant(contextId: String, did: String, amount: UInt64) throws {
        try inner.economyBudgetGrant(contextId: contextId, did: did, amount: amount)
    }

    /// Forwards to ``Scp/economyBudgetRecordSpend`` on ``inner``.
    func economyBudgetRecordSpend(contextId: String, did: String, amount: UInt64) throws {
        try inner.economyBudgetRecordSpend(contextId: contextId, did: did, amount: amount)
    }

    /// Forwards to ``Scp/economyBudgetRemaining`` on ``inner``.
    func economyBudgetRemaining(contextId: String, did: String) throws -> UInt64 {
        try inner.economyBudgetRemaining(contextId: contextId, did: did)
    }

    /// Forwards to ``Scp/economyVerifyPaymentReceipts`` on ``inner``.
    ///
    /// Verifies a batch of payment receipts against the configured payment
    /// adapter. Maximum 10,000 receipts per call. Returns a JSON object
    /// `{"all_valid": <bool>, "results": [...]}`; `all_valid` is vacuously
    /// `true` for an empty batch. Each entry's `ok` means the adapter
    /// *responded* — NOT that the payment is valid; scan `valid`/`all_valid`
    /// for payment validity.
    func economyVerifyPaymentReceipts(receiptsJson: String) async throws -> String {
        try await inner.economyVerifyPaymentReceipts(receiptsJson: receiptsJson)
    }

    /// Forwards to ``Scp/evaluateInvitation`` on ``inner``.
    func evaluateInvitation(paramsJson: String, inviterDid: String, identityDid: String, policyJson: String?, spendingJson: String?) throws -> String {
        try inner.evaluateInvitation(paramsJson: paramsJson, inviterDid: inviterDid, identityDid: identityDid, policyJson: policyJson, spendingJson: spendingJson)
    }

    /// Forwards to ``Scp/eventLogCheckpoint`` on ``inner``.
    func eventLogCheckpoint(handle: ContextHandle, identity: Identity, epoch: UInt64) async throws -> Checkpoint {
        try await inner.eventLogCheckpoint(handle: handle, identity: identity, epoch: epoch)
    }

    /// Forwards to ``Scp/eventLogCheckpointByDid`` on ``inner``.
    func eventLogCheckpointByDid(handle: ContextHandle, identity: Identity, did: String, epoch: UInt64) async throws -> Checkpoint {
        try await inner.eventLogCheckpointByDid(handle: handle, identity: identity, did: did, epoch: epoch)
    }

    /// Forwards to ``Scp/eventLogQuery`` on ``inner``.
    func eventLogQuery(handle: ContextHandle, filterJson: String?) async throws -> [Event] {
        try await inner.eventLogQuery(handle: handle, filterJson: filterJson)
    }

    /// Forwards to ``Scp/eventLogVerify`` on ``inner``.
    func eventLogVerify(handle: ContextHandle, claimJson: String) async throws -> Proof {
        try await inner.eventLogVerify(handle: handle, claimJson: claimJson)
    }

    /// Forwards to ``Scp/finalizeClose`` on ``inner``.
    func finalizeClose(handle: ContextHandle) async throws {
        try await inner.finalizeClose(handle: handle)
    }

    /// Forwards to ``Scp/getEconomicPolicy`` on ``inner``.
    func getEconomicPolicy(handle: ContextHandle) throws -> String? {
        try inner.getEconomicPolicy(handle: handle)
    }

    /// Forwards to ``Scp/governanceApprove`` on ``inner``.
    func governanceApprove(handle: ContextHandle, voterDid: String, proposalIdHex: String) async throws -> String {
        try await inner.governanceApprove(handle: handle, voterDid: voterDid, proposalIdHex: proposalIdHex)
    }

    /// Forwards to ``Scp/governanceExecute`` on ``inner``.
    ///
    /// Executes a previously-approved governance proposal BY ID. The runtime
    /// resolves the authoritative proposal from the context actor's own
    /// quorum-validated governance engine; the caller supplies no proposal,
    /// action, status, or identity. The executor and consequence subject are
    /// resolved from the tracked proposal's proposer.
    func governanceExecute(handle: ContextHandle, proposalIdHex: String) async throws -> String {
        try await inner.governanceExecute(handle: handle, proposalIdHex: proposalIdHex)
    }

    /// Forwards to ``Scp/governanceGetProposal`` on ``inner``.
    func governanceGetProposal(handle: ContextHandle, proposalIdHex: String) async throws -> String {
        try await inner.governanceGetProposal(handle: handle, proposalIdHex: proposalIdHex)
    }

    /// Forwards to ``Scp/governanceListProposals`` on ``inner``.
    func governanceListProposals(handle: ContextHandle) async throws -> String {
        try await inner.governanceListProposals(handle: handle)
    }

    /// Forwards to ``Scp/governancePropose`` on ``inner``.
    func governancePropose(handle: ContextHandle, proposerDid: String, actionJson: String) async throws -> String {
        try await inner.governancePropose(handle: handle, proposerDid: proposerDid, actionJson: actionJson)
    }

    /// Forwards to ``Scp/governanceReject`` on ``inner``.
    func governanceReject(handle: ContextHandle, voterDid: String, proposalIdHex: String) async throws -> String {
        try await inner.governanceReject(handle: handle, voterDid: voterDid, proposalIdHex: proposalIdHex)
    }

    /// Forwards to ``Scp/governanceWithdraw`` on ``inner``.
    func governanceWithdraw(handle: ContextHandle, voterDid: String, proposalIdHex: String) async throws -> String {
        try await inner.governanceWithdraw(handle: handle, voterDid: voterDid, proposalIdHex: proposalIdHex)
    }

    /// Forwards to ``Scp/handleDeregister`` on ``inner``.
    func handleDeregister(discoveryContextId: String, handle: String, did: String) throws -> String {
        try inner.handleDeregister(discoveryContextId: discoveryContextId, handle: handle, did: did)
    }

    /// Forwards to ``Scp/handleLookup`` on ``inner``.
    func handleLookup(discoveryContextId: String, handle: String, typeFilter: String?) throws -> String {
        try inner.handleLookup(discoveryContextId: discoveryContextId, handle: handle, typeFilter: typeFilter)
    }

    /// Forwards to ``Scp/handleRegister`` on ``inner``.
    func handleRegister(discoveryContextId: String, handle: String, targetJson: String, registrantDid: String, description: String?, tags: [String]?) throws -> String {
        try inner.handleRegister(discoveryContextId: discoveryContextId, handle: handle, targetJson: targetJson, registrantDid: registrantDid, description: description, tags: tags)
    }

    /// Forwards to ``Scp/identityAttestDevice`` on ``inner``.
    func identityAttestDevice(identity: Identity) async throws -> String {
        try await inner.identityAttestDevice(identity: identity)
    }

    /// Forwards to ``Scp/identityCreate`` on ``inner``.
    ///
    /// `testingSeed` is a testing-only parameter for the ADR-046
    /// cross-bridge parity harness; pass `nil` from production callers
    /// (the `allow_in_memory_custody` in-memory path uses OS RNG when
    /// `testingSeed` is `nil`). A non-`nil` `testingSeed` is only valid
    /// for `custody == "in_memory"`; other custody types reject it with
    /// `SCP-VALID-7009`.
    func identityCreate(custody: String, testingSeed: Data? = nil) async throws -> Identity {
        try await inner.identityCreate(custody: custody, testingSeed: testingSeed)
    }

    /// Forwards to ``Scp/identityCreateLinkAttestation`` on ``inner``.
    func identityCreateLinkAttestation(identity: Identity, platform: String, handle: String, proof: String, verificationMethod: String, platformId: String?) async throws -> String {
        try await inner.identityCreateLinkAttestation(identity: identity, platform: platform, handle: handle, proof: proof, verificationMethod: verificationMethod, platformId: platformId)
    }

    /// Forwards to ``Scp/identityCreateWithAgentKey`` on ``inner``.
    func identityCreateWithAgentKey(custody: String) async throws -> Identity {
        try await inner.identityCreateWithAgentKey(custody: custody)
    }

    /// Forwards to ``Scp/identityCreateWithCustody`` on ``inner``.
    func identityCreateWithCustody(provider: KeyCustodyProvider) async throws -> Identity {
        try await inner.identityCreateWithCustody(provider: provider)
    }

    /// Forwards to ``Scp/identityExecuteCustodyMigration`` on ``inner``.
    func identityExecuteCustodyMigration(did: String, target: String, contextIds: [String]) throws -> String {
        try inner.identityExecuteCustodyMigration(did: did, target: target, contextIds: contextIds)
    }

    /// Forwards to ``Scp/identityExecuteRecovery`` on ``inner``.
    func identityExecuteRecovery(did: String, tier: String, contextIds: [String]) throws -> String {
        try inner.identityExecuteRecovery(did: did, tier: tier, contextIds: contextIds)
    }

    /// Forwards to ``Scp/identityLinkAttestations`` on ``inner``.
    func identityLinkAttestations(did: String) throws -> String {
        try inner.identityLinkAttestations(did: did)
    }

    /// Forwards to ``Scp/identityLoad`` on ``inner``.
    func identityLoad(did: String) async throws -> Identity {
        try await inner.identityLoad(did: did)
    }

    /// Forwards to ``Scp/identityMigrate`` on ``inner``.
    func identityMigrate(identity: Identity) async throws -> Identity {
        try await inner.identityMigrate(identity: identity)
    }

    /// Forwards to ``Scp/identityRemoveLinkAttestation`` on ``inner``.
    func identityRemoveLinkAttestation(did: String, attestationId: String) -> Bool {
        inner.identityRemoveLinkAttestation(did: did, attestationId: attestationId)
    }

    /// Forwards to ``Scp/identityRemove`` on ``inner``.
    ///
    /// Removes the DID from this instance's SCP-side identity registry.
    /// Idempotent — succeeds silently when the DID is a syntactically valid
    /// DID not present in the registry.
    ///
    /// - Throws: ``ScpError`` when `did` is not a syntactically valid DID,
    ///   mirroring the PyO3 reference bridge's `identity_remove`.
    func identityRemove(did: String) throws {
        try inner.identityRemove(did: did)
    }

    /// Forwards to ``Scp/identityRemoveIfPresent`` on ``inner``.
    ///
    /// Returns `true` if the identity was found and removed, `false` if the
    /// DID was not in the registry.
    ///
    /// - Throws: ``ScpError`` when `did` is not a syntactically valid DID,
    ///   mirroring the PyO3 reference bridge's `identity_remove_if_present`.
    func identityRemoveIfPresent(did: String) throws -> Bool {
        try inner.identityRemoveIfPresent(did: did)
    }

    // `identityResolve`, `identityVerifyDeviceAttestation`, and
    // `identityVerifyLinkAttestation` moved to UniFFI-generated free
    // top-level functions under ADR-048 §1 + §7 Swift bullet. Call them
    // directly:
    //   `try await identityResolve(did:)`
    //   `try await identityVerifyDeviceAttestation(did:tokenBase64:)`
    //   `try identityVerifyLinkAttestation(attestationJson:issuerPublicKeyHex:)`

    /// Forwards to ``Scp/isLocalDid`` on ``inner``.
    func isLocalDid(did: String) async -> Bool {
        await inner.isLocalDid(did: did)
    }

    /// Forwards to ``Scp/mcpClientConnectSse`` on ``inner``.
    func mcpClientConnectSse(url: String) async throws -> String {
        try await inner.mcpClientConnectSse(url: url)
    }

    /// Forwards to ``Scp/mcpClientConnectStdio`` on ``inner``.
    ///
    /// `command[0]` is validated against THIS instance's stdio allowlist
    /// (per-instance — disabling enforcement on another ``SCP`` does not
    /// affect this one). To permit a binary not in the default allowlist,
    /// call ``mcpConfigureStdioAllowlist(additionalBinaries:)`` first; use
    /// ``mcpGetStdioAllowlist()`` to inspect the current state.
    func mcpClientConnectStdio(command: [String]) async throws -> String {
        try await inner.mcpClientConnectStdio(command: command)
    }

    /// Forwards to ``Scp/mcpClientDisconnect`` on ``inner``.
    func mcpClientDisconnect(handle: String) async throws {
        try await inner.mcpClientDisconnect(handle: handle)
    }

    /// Forwards to ``Scp/mcpClientInvoke`` on ``inner``.
    func mcpClientInvoke(handle: String, toolName: String, inputJson: String, contextId: String, invokerDid: String) async throws -> McpInvokeResult {
        try await inner.mcpClientInvoke(handle: handle, toolName: toolName, inputJson: inputJson, contextId: contextId, invokerDid: invokerDid)
    }

    /// Forwards to ``Scp/mcpClientListTools`` on ``inner``.
    func mcpClientListTools(handle: String) async throws -> [McpToolInfo] {
        try await inner.mcpClientListTools(handle: handle)
    }

    /// Forwards to ``Scp/mcpConfigureStdioAllowlist`` on ``inner``.
    func mcpConfigureStdioAllowlist(additionalBinaries: [String]) throws {
        try inner.mcpConfigureStdioAllowlist(additionalBinaries: additionalBinaries)
    }

    /// Disable this instance's stdio allowlist (unrestricted mode).
    ///
    /// After calling this, **any** binary may be spawned by
    /// ``mcpClientConnectStdio`` on this ``SCP``. Other instances are
    /// unaffected. Pass ``iTrustAllCommands: true`` to confirm
    /// acknowledgement of the security implication; the call also emits
    /// an `os_log` / `print` warning for operator audit.
    func mcpDisableStdioAllowlist(iTrustAllCommands: Bool = false) throws {
        guard iTrustAllCommands else {
            throw ScpError.Validation(
                msg: "Disabling the stdio allowlist allows any binary to be spawned by this SCP instance. Pass iTrustAllCommands: true to confirm.",
                code: "SCP-MCP-10010"
            )
        }
        print("[scp] MCP stdio allowlist enforcement disabled — arbitrary subprocess spawning is now permitted on this instance")
        try inner.mcpDisableStdioAllowlist()
    }

    /// Forwards to ``Scp/mcpGetStdioAllowlist`` on ``inner``.
    func mcpGetStdioAllowlist() throws -> McpAllowlistState {
        try inner.mcpGetStdioAllowlist()
    }

    /// Forwards to ``Scp/mcpResetStdioAllowlist`` on ``inner``.
    func mcpResetStdioAllowlist() throws {
        try inner.mcpResetStdioAllowlist()
    }

    /// Forwards to ``Scp/mcpServerCreate`` on ``inner``.
    func mcpServerCreate(config: McpServerConfig) async throws -> String {
        try await inner.mcpServerCreate(config: config)
    }

    /// Forwards to ``Scp/mcpServerStop`` on ``inner``.
    func mcpServerStop(handle: String) async throws {
        try await inner.mcpServerStop(handle: handle)
    }

    /// Forwards to ``Scp/migrationState`` on ``inner``.
    func migrationState(handle: ContextHandle) async throws -> String? {
        try await inner.migrationState(handle: handle)
    }

    /// Forwards to ``Scp/nodeStartInMemory`` on ``inner``.
    func nodeStartInMemory(identity: Identity?) async throws -> NodeHandle {
        try await inner.nodeStartInMemory(identity: identity)
    }

    /// Forwards to ``Scp/nodeStartLocal`` on ``inner``.
    func nodeStartLocal(dataDir: String, identity: Identity?, passphrase: String?) async throws -> NodeHandle {
        try await inner.nodeStartLocal(dataDir: dataDir, identity: identity, passphrase: passphrase)
    }

    /// Forwards to ``Scp/petnameApplyEvent`` on ``inner``.
    func petnameApplyEvent(ownerDid: String, eventJson: String) throws {
        try inner.petnameApplyEvent(ownerDid: ownerDid, eventJson: eventJson)
    }

    /// Forwards to ``Scp/petnameContextCount`` on ``inner``.
    func petnameContextCount(ownerDid: String) throws -> UInt32 {
        try inner.petnameContextCount(ownerDid: ownerDid)
    }

    /// Forwards to ``Scp/petnameDidCount`` on ``inner``.
    func petnameDidCount(ownerDid: String) throws -> UInt32 {
        try inner.petnameDidCount(ownerDid: ownerDid)
    }

    /// Forwards to ``Scp/petnameGetForContext`` on ``inner``.
    func petnameGetForContext(ownerDid: String, contextId: String) throws -> String? {
        try inner.petnameGetForContext(ownerDid: ownerDid, contextId: contextId)
    }

    /// Forwards to ``Scp/petnameGetForDid`` on ``inner``.
    func petnameGetForDid(ownerDid: String, targetDid: String) throws -> String? {
        try inner.petnameGetForDid(ownerDid: ownerDid, targetDid: targetDid)
    }

    /// Forwards to ``Scp/petnameRemove`` on ``inner``.
    func petnameRemove(ownerDid: String, targetDid: String) throws {
        try inner.petnameRemove(ownerDid: ownerDid, targetDid: targetDid)
    }

    /// Forwards to ``Scp/petnameRemoveContext`` on ``inner``.
    func petnameRemoveContext(ownerDid: String, contextId: String) throws {
        try inner.petnameRemoveContext(ownerDid: ownerDid, contextId: contextId)
    }

    /// Forwards to ``Scp/petnameResolveContext`` on ``inner``.
    func petnameResolveContext(ownerDid: String, name: String) throws -> String {
        try inner.petnameResolveContext(ownerDid: ownerDid, name: name)
    }

    /// Forwards to ``Scp/petnameResolveDid`` on ``inner``.
    func petnameResolveDid(ownerDid: String, name: String) throws -> String {
        try inner.petnameResolveDid(ownerDid: ownerDid, name: name)
    }

    /// Forwards to ``Scp/petnameSet`` on ``inner``.
    func petnameSet(ownerDid: String, targetDid: String, name: String) throws {
        try inner.petnameSet(ownerDid: ownerDid, targetDid: targetDid, name: name)
    }

    /// Forwards to ``Scp/petnameSetContext`` on ``inner``.
    func petnameSetContext(ownerDid: String, contextId: String, name: String) throws {
        try inner.petnameSetContext(ownerDid: ownerDid, contextId: contextId, name: name)
    }

    /// Forwards to ``Scp/provenanceAttach`` on ``inner``.
    func provenanceAttach(sourceContextId: String, sourceType: String, memoryScopeStr: String, members: [String], targetContextId: String, actorDid: String, existingChainDepth: UInt8?) throws -> String {
        try inner.provenanceAttach(sourceContextId: sourceContextId, sourceType: sourceType, memoryScopeStr: memoryScopeStr, members: members, targetContextId: targetContextId, actorDid: actorDid, existingChainDepth: existingChainDepth)
    }

    /// Forwards to ``Scp/registerLocalDid`` on ``inner``.
    func registerLocalDid(did: String) async throws {
        try await inner.registerLocalDid(did: did)
    }

    /// Forwards to ``Scp/relayStartInMemory`` on ``inner``.
    func relayStartInMemory() async throws -> RelayHandle {
        try await inner.relayStartInMemory()
    }

    /// Forwards to ``Scp/relayStartLocal`` on ``inner``.
    func relayStartLocal(dataDir: String) async throws -> RelayHandle {
        try await inner.relayStartLocal(dataDir: dataDir)
    }

    /// Forwards to ``Scp/restoreAllContexts`` on ``inner``.
    func restoreAllContexts() async throws -> String {
        try await inner.restoreAllContexts()
    }

    /// Forwards to ``Scp/restoreContext`` on ``inner``.
    func restoreContext(contextId: String) async throws {
        try await inner.restoreContext(contextId: contextId)
    }

    /// Forwards to ``Scp/scopeDeregister`` on ``inner``.
    func scopeDeregister(scopeContextId: String, name: String, did: String) throws -> String {
        try inner.scopeDeregister(scopeContextId: scopeContextId, name: name, did: did)
    }

    /// Forwards to ``Scp/scopeLookup`` on ``inner``.
    func scopeLookup(scopeContextId: String, name: String) throws -> String {
        try inner.scopeLookup(scopeContextId: scopeContextId, name: name)
    }

    /// Forwards to ``Scp/scopeRegister`` on ``inner``.
    func scopeRegister(scopeContextId: String, name: String, targetContextId: String, relayUrls: [String], registrantDid: String, description: String?, tags: [String]?) throws -> String {
        try inner.scopeRegister(scopeContextId: scopeContextId, name: name, targetContextId: targetContextId, relayUrls: relayUrls, registrantDid: registrantDid, description: description, tags: tags)
    }

    /// Forwards to ``Scp/scpidSign`` on ``inner``.
    ///
    /// `signedAtOverride` is a testing-only parameter for the ADR-046
    /// cross-bridge parity harness; pass `nil` from production callers.
    /// Production builds reject non-`nil` values with `SCP-VALID-7008`.
    func scpidSign(identity: Identity, signingKeyId: String, challengeJson: String, signedAtOverride: UInt64? = nil) throws -> String {
        try inner.scpidSign(identity: identity, signingKeyId: signingKeyId, challengeJson: challengeJson, signedAtOverride: signedAtOverride)
    }

    /// Forwards to ``Scp/scpidVerify`` on ``inner``.
    func scpidVerify(responseJson: String, challengeJson: String) throws -> String {
        try inner.scpidVerify(responseJson: responseJson, challengeJson: challengeJson)
    }

    // MARK: - Bridge credential store (spec §12.11)

    //
    // Per-instance credential store ops. Each forwards to ``inner`` — the
    // credentials live in THIS instance's store (ADR-048 §1). The encrypted
    // credential bytes never cross the FFI boundary; only metadata is
    // returned for provision/rotate.

    /// Provisions (stores) an encrypted credential for a bridge instance.
    /// Forwards to ``Scp/bridgeCredentialProvision`` on ``inner``.
    func bridgeCredentialProvision(
        bridgeId: String,
        credentialType: String,
        plaintext: Data,
        bridgeCredentialKey: Data
    ) throws -> BridgeCredentialResult {
        try inner.bridgeCredentialProvision(
            bridgeId: bridgeId,
            credentialType: credentialType,
            plaintext: plaintext,
            bridgeCredentialKey: bridgeCredentialKey
        )
    }

    /// Retrieves and decrypts a credential for a bridge instance.
    /// Forwards to ``Scp/bridgeCredentialRetrieve`` on ``inner``.
    func bridgeCredentialRetrieve(
        bridgeId: String,
        credentialType: String,
        bridgeCredentialKey: Data
    ) throws -> Data {
        try inner.bridgeCredentialRetrieve(
            bridgeId: bridgeId,
            credentialType: credentialType,
            bridgeCredentialKey: bridgeCredentialKey
        )
    }

    /// Rotates (replaces) a credential for a bridge instance.
    /// Forwards to ``Scp/bridgeCredentialRotate`` on ``inner``.
    func bridgeCredentialRotate(
        bridgeId: String,
        credentialType: String,
        newPlaintext: Data,
        bridgeCredentialKey: Data
    ) throws -> BridgeCredentialResult {
        try inner.bridgeCredentialRotate(
            bridgeId: bridgeId,
            credentialType: credentialType,
            newPlaintext: newPlaintext,
            bridgeCredentialKey: bridgeCredentialKey
        )
    }

    /// Revokes all credentials for a bridge instance.
    /// Forwards to ``Scp/bridgeCredentialRevoke`` on ``inner``.
    func bridgeCredentialRevoke(bridgeId: String) throws {
        try inner.bridgeCredentialRevoke(bridgeId: bridgeId)
    }

    /// Lists all credential types stored for a bridge instance.
    /// Forwards to ``Scp/bridgeCredentialList`` on ``inner``.
    func bridgeCredentialList(bridgeId: String) throws -> [String] {
        try inner.bridgeCredentialList(bridgeId: bridgeId)
    }

    /// Stores a bridge credential key in the custody boundary.
    /// Forwards to ``Scp/bridgeCredentialStoreKey`` on ``inner``.
    func bridgeCredentialStoreKey(bridgeId: String, key: Data) throws {
        try inner.bridgeCredentialStoreKey(bridgeId: bridgeId, key: key)
    }

    /// Retrieves a bridge credential key from the custody boundary.
    /// Forwards to ``Scp/bridgeCredentialGetKey`` on ``inner``.
    func bridgeCredentialGetKey(bridgeId: String) throws -> Data {
        try inner.bridgeCredentialGetKey(bridgeId: bridgeId)
    }

    /// Deletes and zeroizes a bridge credential key.
    /// Forwards to ``Scp/bridgeCredentialDeleteKey`` on ``inner``.
    func bridgeCredentialDeleteKey(bridgeId: String) throws {
        try inner.bridgeCredentialDeleteKey(bridgeId: bridgeId)
    }

    /// Forwards to ``Scp/setEconomicPolicy`` on ``inner``.
    func setEconomicPolicy(handle: ContextHandle, policyJson: String) throws {
        try inner.setEconomicPolicy(handle: handle, policyJson: policyJson)
    }

    // `syncClassifyOffline`, `syncClassifyOfflineCustom`, and `syncGetPolicy`
    // moved to UniFFI-generated free top-level functions under
    // ADR-048 §1 + §7 Swift bullet. Call them directly:
    //   `syncClassifyOffline(lastRelayContact:now:)`
    //   `syncClassifyOfflineCustom(lastRelayContact:now:tier1ThresholdSecs:tier2ThresholdSecs:)`
    //   `syncGetPolicy()`

    /// Forwards to ``Scp/tombstoneMigratedContext`` on ``inner``.
    func tombstoneMigratedContext(handle: ContextHandle) async throws {
        try await inner.tombstoneMigratedContext(handle: handle)
    }

    /// Forwards to ``Scp/toolInterfaceAccept`` on ``inner``.
    func toolInterfaceAccept(handle: ContextHandle, interfaceJson: String) async throws -> String {
        try await inner.toolInterfaceAccept(handle: handle, interfaceJson: interfaceJson)
    }

    /// Forwards to ``Scp/toolInterfaceExpose`` on ``inner``.
    func toolInterfaceExpose(handle: ContextHandle, toolId: String, targetContextId: String, rateLimitJson: String?) async throws -> String {
        try await inner.toolInterfaceExpose(handle: handle, toolId: toolId, targetContextId: targetContextId, rateLimitJson: rateLimitJson)
    }

    /// Forwards to ``Scp/toolInterfaceRevoke`` on ``inner``.
    func toolInterfaceRevoke(handle: ContextHandle, interfaceIdHex: String) async throws -> String {
        try await inner.toolInterfaceRevoke(handle: handle, interfaceIdHex: interfaceIdHex)
    }

    /// Forwards to ``Scp/toolInvoke`` on ``inner``.
    func toolInvoke(handle: ContextHandle, toolId: String, inputJson: String, identity: Identity, ucanToken: String?, proofTokens: [String]?, spendingUcanJwt: String?) async throws -> String {
        try await inner.toolInvoke(handle: handle, toolId: toolId, inputJson: inputJson, identity: identity, ucanToken: ucanToken, proofTokens: proofTokens, spendingUcanJwt: spendingUcanJwt)
    }

    /// Forwards to ``Scp/toolInvokeCrossContext`` on ``inner``.
    func toolInvokeCrossContext(sourceHandle: ContextHandle, targetHandle: ContextHandle, toolId: String, inputJson: String, identity: Identity, ucanToken: String, chainDepth: UInt8, proofTokens: [String]?) async throws -> String {
        try await inner.toolInvokeCrossContext(sourceHandle: sourceHandle, targetHandle: targetHandle, toolId: toolId, inputJson: inputJson, identity: identity, ucanToken: ucanToken, chainDepth: chainDepth, proofTokens: proofTokens)
    }

    // swiftlint:disable function_parameter_count
    /// Forwards to ``Scp/toolInvokeCrossContextSaga`` on ``inner``.
    func toolInvokeCrossContextSaga(sourceHandle: ContextHandle, targetHandle: ContextHandle, callerDid: String, toolRegistrationId: String, inputJson: String, assertedNonceHex: String, timestampMs: UInt64, chainDepth: UInt8, ucanProofId: String?) async throws -> SagaResult {
        try await inner.toolInvokeCrossContextSaga(sourceHandle: sourceHandle, targetHandle: targetHandle, callerDid: callerDid, toolRegistrationId: toolRegistrationId, inputJson: inputJson, assertedNonceHex: assertedNonceHex, timestampMs: timestampMs, chainDepth: chainDepth, ucanProofId: ucanProofId)
    }

    // swiftlint:enable function_parameter_count

    /// Forwards to ``Scp/toolRegister`` on ``inner``.
    func toolRegister(handle: ContextHandle, definition: ToolDefinition) async throws -> String {
        try await inner.toolRegister(handle: handle, definition: definition)
    }

    /// Forwards to ``Scp/toolSessionClose`` on ``inner``.
    func toolSessionClose(handle: ContextHandle, sessionId: String) async throws {
        try await inner.toolSessionClose(handle: handle, sessionId: sessionId)
    }

    /// Forwards to ``Scp/toolSessionCreate`` on ``inner``.
    func toolSessionCreate(handle: ContextHandle, toolId: String, sourceContextId: String, ttlSeconds: UInt64?) async throws -> String {
        try await inner.toolSessionCreate(handle: handle, toolId: toolId, sourceContextId: sourceContextId, ttlSeconds: ttlSeconds)
    }

    /// Forwards to ``Scp/toolSessionInvoke`` on ``inner``.
    func toolSessionInvoke(handle: ContextHandle, sessionId: String, inputJson: String, identity: Identity, ucanToken: String, proofTokens: [String]?) async throws -> String {
        try await inner.toolSessionInvoke(handle: handle, sessionId: sessionId, inputJson: inputJson, identity: identity, ucanToken: ucanToken, proofTokens: proofTokens)
    }

    /// Forwards to ``Scp/toolVerify`` on ``inner``.
    func toolVerify(handle: ContextHandle, toolId: String) async throws -> ToolVerificationResult {
        try await inner.toolVerify(handle: handle, toolId: toolId)
    }

    /// Forwards to ``Scp/transportConnect`` on ``inner``.
    func transportConnect(relayUrl: String) async throws -> TransportManager {
        try await inner.transportConnect(relayUrl: relayUrl)
    }

    /// Forwards to ``Scp/transportDisconnect`` on ``inner``.
    func transportDisconnect(manager: TransportManager) async throws {
        try await inner.transportDisconnect(manager: manager)
    }

    /// Forwards to ``Scp/transportStatus`` on ``inner``.
    func transportStatus(manager: TransportManager) async throws -> TransportStatus {
        try await inner.transportStatus(manager: manager)
    }

    /// Forwards to ``Scp/trustCreateChallenge`` on ``inner``.
    func trustCreateChallenge(targetDid: String) throws -> ChallengeResult {
        try inner.trustCreateChallenge(targetDid: targetDid)
    }

    // `trustQueryScore` and `trustVerifyAttestation` moved to UniFFI-generated
    // free top-level functions under ADR-048 §1 + §7 Swift bullet. Call
    // them directly:
    //   `try trustQueryScore(did:contextId:)`
    //   `try trustVerifyAttestation(attestationJson:)`

    /// Forwards to ``Scp/trustVerifyResponse`` on ``inner``.
    func trustVerifyResponse(challengeJson: String, responseJson: String) throws -> Bool {
        try inner.trustVerifyResponse(challengeJson: challengeJson, responseJson: responseJson)
    }

    /// Forwards to ``Scp/ucanDelegate`` on ``inner``.
    func ucanDelegate(handle: ContextHandle, delegatorDid: String, delegateeDid: String, parentToken: String, capabilities: [String]) async throws -> UcanToken {
        try await inner.ucanDelegate(handle: handle, delegatorDid: delegatorDid, delegateeDid: delegateeDid, parentToken: parentToken, capabilities: capabilities)
    }

    /// Forwards to ``Scp/ucanMint`` on ``inner``.
    func ucanMint(handle: ContextHandle, memberDid: String, capabilities: [String], proofs: [String]?) async throws -> UcanToken {
        try await inner.ucanMint(handle: handle, memberDid: memberDid, capabilities: capabilities, proofs: proofs)
    }

    /// Forwards to ``Scp/ucanRevoke`` on ``inner``.
    func ucanRevoke(handle: ContextHandle, token: String, revokerDid: String) async throws {
        try await inner.ucanRevoke(handle: handle, token: token, revokerDid: revokerDid)
    }

    /// Forwards to ``Scp/ucanValidate`` on ``inner``.
    func ucanValidate(handle: ContextHandle, token: String, capability: String, presentingAgentDid: String?, proofTokens: [String]?) async throws {
        try await inner.ucanValidate(handle: handle, token: token, capability: capability, presentingAgentDid: presentingAgentDid, proofTokens: proofTokens)
    }

    // `verifyParticipationRequirements` moved to a UniFFI-generated free
    // top-level function under ADR-048 §1 + §7 Swift bullet. Call it
    // directly:
    //   `try verifyParticipationRequirements(profileJson:requirementsJson:)`
}
