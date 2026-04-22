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
/// ```swift
/// let scp = SCP()                                // fresh in-memory instance
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

    /// Constructs a fresh `SCP` instance with default in-memory state.
    ///
    /// Equivalent to the UniFFI `Scp()` constructor. No state is shared
    /// with other `SCP` instances.
    public init() {
        inner = Scp()
    }

    /// Wraps an already-existing UniFFI `Scp` handle. Internal — used by
    /// the `withStorage(_:)` factories so they can reuse the stored-handle
    /// path without leaking the opaque type.
    init(inner: Scp) {
        self.inner = inner
    }

    /// Constructs an `SCP` with an explicit storage configuration.
    ///
    /// Phase 4 PR 3 (closes #1260 / #1491) added
    /// ``StorageConfig/sqlite(path:key:)`` alongside the default
    /// ``StorageConfig/inMemory`` variant; callers who want a Swift-native
    /// `URL` + `Data` surface over the SQLite variant should prefer
    /// ``SCP/withStorage(sqliteDir:key:)``.
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
    /// If the underlying database cannot be opened (bad key, unreadable
    /// directory) the Rust layer logs via `tracing::error!` and returns
    /// an in-memory-only instance — matching the PyO3 / NAPI fallback
    /// behavior documented in PR 3.
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
    ///
    /// Closes #1260, #1491 (Swift SDK surface).
    public static func withStorage(sqliteDir: URL, key: Data) throws -> SCP {
        try SCP(inner: Scp.withStorage(config: .sqlite(path: sqliteDir.path, key: key)))
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
        let millis: UInt64
        if timeout.isNaN || timeout <= 0 {
            millis = 0
        } else if timeout.isInfinite || timeout >= Double(UInt64.max) / 1000.0 {
            millis = UInt64.max
        } else {
            millis = UInt64((timeout * 1000).rounded())
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

    /// Forwards to ``Scp/bridgeEvaluateTrust`` on ``inner``.
    func bridgeEvaluateTrust(isBridged: Bool, isNativeTransport: Bool, shadowStatus: String) throws -> UInt8 {
        try inner.bridgeEvaluateTrust(isBridged: isBridged, isNativeTransport: isNativeTransport, shadowStatus: shadowStatus)
    }

    /// Forwards to ``Scp/broadcastAdmission`` on ``inner``.
    func broadcastAdmission(handle: ContextHandle) async -> String? {
        await inner.broadcastAdmission(handle: handle)
    }

    /// Forwards to ``Scp/broadcastBlockSubscriber`` on ``inner``.
    func broadcastBlockSubscriber(handle: ContextHandle, subscriberDid: String, blockerDid: String) async throws {
        try await inner.broadcastBlockSubscriber(handle: handle, subscriberDid: subscriberDid, blockerDid: blockerDid)
    }

    /// Forwards to ``Scp/broadcastHandleKeyRequest`` on ``inner``.
    func broadcastHandleKeyRequest(handle: ContextHandle, authorDid: String, requesterDid: String) async throws -> String {
        try await inner.broadcastHandleKeyRequest(handle: handle, authorDid: authorDid, requesterDid: requesterDid)
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
    func contextImport(data: Data) async throws -> String {
        try await inner.contextImport(data: data)
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

    /// Forwards to ``Scp/evaluateInvitation`` on ``inner``.
    func evaluateInvitation(paramsJson: String, inviterDid: String, identityDid: String, policyJson: String?, spendingJson: String?, trustedDids: [String]) throws -> String {
        try inner.evaluateInvitation(paramsJson: paramsJson, inviterDid: inviterDid, identityDid: identityDid, policyJson: policyJson, spendingJson: spendingJson, trustedDids: trustedDids)
    }

    /// Forwards to ``Scp/eventLogCheckpoint`` on ``inner``.
    func eventLogCheckpoint(handle: ContextHandle, identity: Identity, epoch: UInt64) async throws -> Checkpoint {
        try await inner.eventLogCheckpoint(handle: handle, identity: identity, epoch: epoch)
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
    func governanceExecute(handle: ContextHandle, proposalJson: String) async throws -> String {
        try await inner.governanceExecute(handle: handle, proposalJson: proposalJson)
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
    func identityCreate(custody: String) async throws -> Identity {
        try await inner.identityCreate(custody: custody)
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

    /// Forwards to ``Scp/identityResolve`` on ``inner``.
    func identityResolve(did: String) async throws -> DidDocument {
        try await inner.identityResolve(did: did)
    }

    /// Forwards to ``Scp/identityVerifyDeviceAttestation`` on ``inner``.
    func identityVerifyDeviceAttestation(did: String, tokenBase64: String) async throws -> Bool {
        try await inner.identityVerifyDeviceAttestation(did: did, tokenBase64: tokenBase64)
    }

    /// Forwards to ``Scp/identityVerifyLinkAttestation`` on ``inner``.
    func identityVerifyLinkAttestation(attestationJson: String, issuerPublicKeyHex: String) async throws -> Bool {
        try await inner.identityVerifyLinkAttestation(attestationJson: attestationJson, issuerPublicKeyHex: issuerPublicKeyHex)
    }

    /// Forwards to ``Scp/isLocalDid`` on ``inner``.
    func isLocalDid(did: String) async -> Bool {
        await inner.isLocalDid(did: did)
    }

    /// Forwards to ``Scp/mcpClientConnectSse`` on ``inner``.
    func mcpClientConnectSse(url: String) async throws -> String {
        try await inner.mcpClientConnectSse(url: url)
    }

    /// Forwards to ``Scp/mcpClientConnectStdio`` on ``inner``.
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

    /// Forwards to ``Scp/mcpDisableStdioAllowlist`` on ``inner``.
    func mcpDisableStdioAllowlist() throws {
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
    func scpidSign(identity: Identity, signingKeyId: String, challengeJson: String) throws -> String {
        try inner.scpidSign(identity: identity, signingKeyId: signingKeyId, challengeJson: challengeJson)
    }

    /// Forwards to ``Scp/scpidVerify`` on ``inner``.
    func scpidVerify(responseJson: String, challengeJson: String) throws -> String {
        try inner.scpidVerify(responseJson: responseJson, challengeJson: challengeJson)
    }

    /// Forwards to ``Scp/setEconomicPolicy`` on ``inner``.
    func setEconomicPolicy(handle: ContextHandle, policyJson: String) throws {
        try inner.setEconomicPolicy(handle: handle, policyJson: policyJson)
    }

    /// Forwards to ``Scp/syncClassifyOffline`` on ``inner``.
    func syncClassifyOffline(lastRelayContact: UInt64, now: UInt64) -> String {
        inner.syncClassifyOffline(lastRelayContact: lastRelayContact, now: now)
    }

    /// Forwards to ``Scp/syncClassifyOfflineCustom`` on ``inner``.
    func syncClassifyOfflineCustom(lastRelayContact: UInt64, now: UInt64, tier1ThresholdSecs: UInt64, tier2ThresholdSecs: UInt64) -> String {
        inner.syncClassifyOfflineCustom(lastRelayContact: lastRelayContact, now: now, tier1ThresholdSecs: tier1ThresholdSecs, tier2ThresholdSecs: tier2ThresholdSecs)
    }

    /// Forwards to ``Scp/syncGetPolicy`` on ``inner``.
    func syncGetPolicy() -> SyncPolicyResult {
        inner.syncGetPolicy()
    }

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

    /// Forwards to ``Scp/trustQueryScore`` on ``inner``.
    func trustQueryScore(did: String, contextId: String) throws -> TrustScoreResult {
        try inner.trustQueryScore(did: did, contextId: contextId)
    }

    /// Forwards to ``Scp/trustVerifyAttestation`` on ``inner``.
    func trustVerifyAttestation(attestationJson: String) throws -> AttestationVerificationResult {
        try inner.trustVerifyAttestation(attestationJson: attestationJson)
    }

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

    /// Forwards to ``Scp/verifyParticipationRequirements`` on ``inner``.
    func verifyParticipationRequirements(profileJson: String, requirementsJson: String) throws -> Bool {
        try inner.verifyParticipationRequirements(profileJson: profileJson, requirementsJson: requirementsJson)
    }
}
