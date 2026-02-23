# Phase 4 Architecture Decision Records — Trust, Lifecycle, Discovery, Provenance, FFI Foundations

**Date:** February 23, 2026
**Phase goal:** Full trust model, context lifecycle enforcement, cross-context discovery, data provenance. TypeScript SDK foundations.
**Timeline:** Weeks 13-16
**Dependencies between ADRs:**

```
ADR-001..016 (Phase 1-3)
       |
       v
ADR-017 (Trust) ─────────── ADR-019 (Provenance)
       |                          |
       v                          v
ADR-018 (TTL/Scope)       ADR-020 (Discovery)
                                  |
                          ADR-021 (UniFFI) <── Phase 1-2 Rust API
                                  |
                          ADR-022 (TypeScript) <── ADR-021 + Phase 1-3
```

Build order: ADR-017 + ADR-019 (parallel, both depend on Phase 1-3) --> ADR-018 + ADR-020 (parallel) --> ADR-021 (depends on Phase 1-2 Rust API) --> ADR-022 (depends on ADR-021)

---

## ADR-017: Trust Engine (Four-Layer Evaluation)

**Status:** Decided

### Context

Spec §7 defines four layers of trust evaluation, from hardest (pure validation) to softest (pure judgment). Layer 1 (UCAN enforcement) was implemented in ADR-016. The trust engine implements Layers 2-4: behavioral validation (verifiable event logs), behavioral records, attestation verification, challenge-response, and consequence evaluation. The trust engine provides validated inputs for agent-level evaluation — it does not produce trust "scores."

### Decision

Implement `scp-core/trust/` module. Behavioral records are computed locally from event logs (not stored centrally) — any agent computes from accessible logs. Attestation verification follows the common envelope format (§7.4.1). Challenge-response protocol enables verification of testable capabilities. Consequence rules are declared at context creation and protocol-enforced. Trust evaluation is agent-level — the engine provides validated inputs, not decisions.

### Rationale

- **Agent-level evaluation over protocol scores:** Trust is contextual (protocol tenet). The engine provides verifiable facts (behavioral records, verified attestations, challenge results, consequence structures), and each agent's trust evaluation logic consumes these facts according to its own criteria. No universal trust score.
- **Local computation over central storage:** Behavioral records are derived from event logs that every member has. No central behavioral database. Two agents may compute different records from different event log views — this is correct behavior, not a bug.
- **Common attestation envelope:** Uniform structure for all attestation types (§7.4.1) enables generic verification logic and interoperable attestation exchange.
- **Declared consequence rules:** Consequences are part of the opt-in contract — visible before joining, protocol-enforced, verifiable. No hidden penalties.

### Implementation

- **Language:** Rust
- **Crate:** `scp-core`
- **Module:** `scp-core/trust/`
- **Dependencies:** `sha2` (hashing), `ed25519-dalek` (signature verification)

### Dependencies

- **ADR-011 (Event Log):** Behavioral records are derived from event log entries.
- **ADR-016 (UCAN):** Layer 1 enforcement. Trust engine operates on Layers 2-4.
- **ADR-009 (Roles/Capabilities):** Governance action types, role history.

### Acceptance Criteria

1. **Key types:**

```rust
/// Verifiable facts computed from context event logs.
pub struct BehavioralRecord {
    pub subject_did: DID,
    pub context_id: ContextId,
    pub participation_count: u64,
    pub participation_duration_seconds: u64,
    pub tool_invocations: HashMap<ToolId, u64>,
    pub governance_actions_by: Vec<GovernanceActionSummary>,
    pub governance_actions_against: Vec<GovernanceActionSummary>,
    pub role_history: Vec<RoleTransition>,
    pub attestation_history: Vec<AttestationReference>,
    pub context_creation_count: u64,
    pub computed_at: u64,
    pub event_log_root: [u8; 32],  // Merkle root at computation time
}

/// Common attestation envelope (§7.4.1).
pub struct Attestation {
    pub id: String,
    pub attestation_type: AttestationType,
    pub issuer: DID,
    pub subject: DID,
    pub claim: serde_json::Value,
    pub evidence: Option<AttestationEvidence>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub renewal_interval: Option<Duration>,
    pub revocation_status: RevocationStatus,
    pub signature: Ed25519Signature,
}

pub enum AttestationType {
    IdentityLink,
    CapabilityDelegation,
    ToolIntegrity,
    AgentCapability,
    Endorsement,
    RoleAssignment,
    ContextEndorsement,
    BehavioralWitness,
}

pub struct ChallengeRequest {
    pub challenge_id: String,
    pub challenge_type: ChallengeType,
    pub challenger_did: DID,
    pub subject_did: DID,
    pub parameters: serde_json::Value,
    pub timeout: Duration,
    pub signature: Ed25519Signature,
}

pub struct ChallengeResponse {
    pub challenge_id: String,
    pub responder_did: DID,
    pub result: serde_json::Value,
    pub completed_at: u64,
    pub signature: Ed25519Signature,
}

pub struct ConsequenceRule {
    pub trigger: ConsequenceTrigger,
    pub action: ConsequenceAction,
    pub threshold: u64,
    pub window: Duration,
}

pub enum ConsequenceTrigger {
    MessageVelocity,
    ToolRateExceeded,
    WarningCount,
    Custom(String),
}

pub enum ConsequenceAction {
    CapabilitySuspension(Vec<Capability>),
    AccessRevocation,
    RoleDemotion { to_role: String },
}

pub struct ThresholdRequirement {
    pub required_count: u32,          // N
    pub total_attestors: u32,         // M
    pub independence_threshold: f64,  // Minimum independence score (0.0-1.0)
}

/// Aggregated trust inputs for agent-level evaluation.
pub struct TrustInput {
    pub verified_attestations: Vec<Attestation>,
    pub behavioral_record: BehavioralRecord,
    pub challenge_results: Vec<(ChallengeRequest, ChallengeResponse)>,
    pub consequence_structure: Vec<ConsequenceRule>,
    pub threshold_counts: HashMap<AttestationType, (u32, u32)>,  // (met, required)
}
```

2. **`compute_behavioral_record(event_log, subject_did) -> Result<BehavioralRecord, TrustError>`**
   - Scans event log entries for the subject DID.
   - Computes: participation count/duration, tool invocations by type/frequency, governance actions against/by identity, role progression, attestation history, context creation history.
   - Captures the Merkle root at computation time for verifiability.
   - Pure computation — no side effects, no storage.

3. **`verify_attestation(attestation) -> Result<(), TrustError>`**
   - Verifies Ed25519 signature against issuer's public key (resolved via DID).
   - Validates evidence per attestation type.
   - Checks expiry: rejects if `expires_at < now`.
   - Checks revocation: queries revocation status.
   - Returns specific error variant on failure.

4. **`issue_challenge(challenger_did, subject_did, challenge_type, params) -> ChallengeRequest`**
   - Constructs and signs a challenge request.
   - Standard challenge suites: prompt injection resistance, schema validation, rate limit compliance.

5. **`verify_challenge_response(request, response) -> Result<ChallengeVerification, TrustError>`**
   - Verifies response signature against responder's DID.
   - Validates response matches the challenge parameters.
   - Distinguishes self-attested vs challenge-verified in metadata.

6. **`evaluate_consequence_rules(rules, event_log, subject_did) -> Vec<TriggeredConsequence>`**
   - Checks each rule's trigger condition against event log data within the rule's time window.
   - Message velocity threshold -> capability suspension.
   - Tool rate threshold -> access revocation.
   - Warning count -> role demotion.
   - Returns list of triggered consequences with the triggering evidence.

7. **`check_threshold_attestation(attestation_type, attestors, requirement) -> ThresholdResult`**
   - Counts attestations of the given type from the attestor set.
   - Verifies independence: shared context memberships and mutual endorsements reduce independence score.
   - Returns whether the N-of-M threshold is met with sufficient independence.

8. **`check_attestation_freshness(attestation) -> FreshnessStatus`**
   - Evaluates renewal interval. Stale attestations (past renewal interval but not expired) are degraded, not revoked.
   - Returns `Fresh`, `Stale { since }`, or `Expired`.

9. **`aggregate_trust_input(context, subject_did) -> Result<TrustInput, TrustError>`**
   - Computes behavioral record from event log.
   - Collects and verifies attestations from cache.
   - Collects challenge results with timestamps.
   - Collects consequence structure from context params.
   - Computes threshold counts per attestation type.
   - Returns the complete `TrustInput` struct for agent-level evaluation.

10. **ProtocolStore integration:**
    - Cache verified attestations with TTL-based refresh.
    - Store revocation list state per context.
    - Persist challenge results with timestamps.

### Scope

**Files (~6):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `TrustInput`, re-exports |
| `behavioral.rs` | `BehavioralRecord`, `compute_behavioral_record` |
| `attestation.rs` | `Attestation`, `AttestationType`, `verify_attestation`, `check_attestation_freshness`, `check_threshold_attestation` |
| `challenge.rs` | `ChallengeRequest`, `ChallengeResponse`, `issue_challenge`, `verify_challenge_response` |
| `consequence.rs` | `ConsequenceRule`, `evaluate_consequence_rules` |
| `aggregate.rs` | `aggregate_trust_input` — combines all layers into `TrustInput` |

**Estimated functions:** ~20 public functions, ~12 internal helpers.

---

## ADR-018: Context TTL and Memory Scope Enforcement

**Status:** Decided

### Context

Spec §5.10 defines TTL semantics and §5.11 defines memory scope. Contexts gain declared lifespan (TTL) and data retention policy (memory scope). Memory scope drives key destruction behavior on context close — Ephemeral destroys keys immediately, Summary destroys after a verification window, Full preserves everything. Key destruction makes content physically unreadable, enforced by cryptography rather than policy. Promotion (§5.10) is a governed state transition from ephemeral to persistent requiring unanimous consent.

### Decision

Implement TTL tracking and memory scope enforcement in `scp-core/context/`. TTL is tracked per-context via ProtocolStore. Memory scope drives key destruction behavior on context close. Promotion requires unanimous member consent because it changes the opt-in contract. Broadcast contexts are restricted to `Full` scope only — MLS-based forward secrecy is unavailable in broadcast mode.

### Rationale

- **Key destruction as enforcement:** Access control via key destruction is mathematically enforced, not policy-dependent. Destroying MLS tree secrets, epoch key schedules, and application key material makes all historical content physically unreadable — no trust in relay deletion compliance required.
- **Promotion as contract change:** Moving from ephemeral to persistent changes what members opted into. Unanimous consent (not just governance majority) is required because the original scope was part of the opt-in contract visible before joining (protocol tenet: legibility before opt-in).
- **Broadcast scope restriction:** Broadcast contexts (§5.14) use per-author keys without MLS group management. Forward secrecy depends on MLS epoch ratcheting, which broadcast mode lacks. Ephemeral/Summary scopes promise key destruction semantics that broadcast mode cannot deliver. Restricting to Full scope avoids false security guarantees.
- **Key destruction verification levels:** The protocol records attestation level (hardware-backed, software-only, no attestation) as metadata. It does not gate on level — the protocol works regardless, but higher assurance levels are visible to other participants.

### Implementation

- **Language:** Rust
- **Crate:** `scp-core`
- **Module:** `scp-core/context/` (additions to existing context module)
- **Timer:** tokio timer tasks for TTL enforcement
- **Clock:** `Clock` trait from §16.3 for testable time

### Dependencies

- **ADR-008 (Context Lifecycle):** TTL and memory scope are enforced through the context state machine. Close triggers follow the state machine transitions.
- **ADR-001 (MLS):** Key destruction calls `destroy_group()` to eliminate all MLS group state.
- **ADR-006 (Platform Abstraction):** Key destruction attestation level depends on platform adapter (Secure Enclave = hardware-attested, software keys = software-only).

### Acceptance Criteria

1. **Key types:**

```rust
pub enum TtlPolicy {
    None,
    Finite(Duration),
}

pub enum PromotionPolicy {
    NoPromotion,
    Promotable,
}

pub enum MemoryScope {
    Ephemeral,
    Summary,
    Full,
}

pub enum ContextCloseReason {
    TtlExpired,
    GovernanceClosed,
    AllMembersLeft,
}

pub enum KeyDestructionLevel {
    HardwareAttested,
    SoftwareOnly,
    NoAttestation,
}

pub struct RelayDeletionRequest {
    pub relay_url: String,
    pub blob_ids: Vec<BlobId>,
    pub context_id: ContextId,
    pub requested_at: u64,
}
```

2. **TTL enforcement:**
   - TTL checked against `Clock` trait (§16.3) on every context action.
   - TTL expiry triggers context close — no new actions accepted after expiry.
   - TTL timer spawned at context creation via tokio. Timer fires at expiry and calls `handle_ttl_expiry()`.
   - Timer cancelled if context closes before TTL.

3. **TTL extension:**
   - Bilateral contexts require all-member consent.
   - Multi-party contexts follow governance model.
   - Extension proposal is a context event in the Merkle log (ADR-011).
   - Extension resets the TTL timer.

4. **Promotion (ephemeral to persistent):**
   - Only `promotable` contexts can be promoted. `no_promotion` contexts reject promotion proposals.
   - Requires unanimous member consent (not just governance majority).
   - On promotion: TTL removed, memory scope transitions to `Full`, existing event log and key material preserved.
   - Promotion is a context event in the Merkle log.

5. **Ephemeral close:**
   - Destroy MLS group state: tree secrets, all epoch key schedules, application key material via MLS wrapper (ADR-001 `destroy_group`).
   - Destroy all sender keys for this context (ADR-007).
   - Issue `RelayDeletionRequest` for all encrypted event data.

6. **Summary close:**
   - Open verification window (configurable, default defined per context).
   - Participants verify summary against event log during the window.
   - After window closes, destroy keys as ephemeral (step 5).

7. **Key destruction verification:**
   - Platform provides attestation per `KeyDestructionLevel` (§9.15).
   - Hardware-attested (Secure Enclave/Keystore) > software-only > no attestation.
   - Verification level is metadata recorded in the close event — not a gate. The protocol records what level of assurance was achieved.

8. **Relay deletion tracking:**
   - Relay responses to deletion requests tracked.
   - Non-compliant relays deprioritized for future context creation (feeds into relay reliability scoring, ADR-012 `ReliabilityScore.deletion_compliance_rate`).

9. **Broadcast context restriction:**
   - `MemoryScope::Full` only for broadcast contexts.
   - Reject `Ephemeral` or `Summary` at creation time — return `ContextError::InvalidMemoryScopeForBroadcast`.

### Scope

**Files (~4):**

| File | Purpose |
|------|---------|
| `ttl.rs` | TTL timer management, `TtlPolicy`, extension proposal handling, expiry trigger (extends existing stub from ADR-008) |
| `memory_scope.rs` | `MemoryScope`, `PromotionPolicy`, `KeyDestructionLevel`, key destruction orchestration, relay deletion tracking |
| `promotion.rs` | Promotion proposal, unanimous consent collection, scope transition logic |
| `close.rs` | Close orchestration per `ContextCloseReason`, summary verification window, key destruction sequencing |

**Estimated functions:** ~15 public functions, ~10 internal helpers.

---

## ADR-019: Data Provenance

**Status:** Decided

### Context

Provenance is a core protocol principle (§1, tenet 1): "All non-private data carries verifiable origin metadata." Spec §7.7 defines the provenance format (§7.7.1) and quality evaluation tiers (§7.7.2). Provenance is attached automatically by the protocol when data crosses context boundaries through protocol mechanisms (tool interfaces §6.2, structured messages). The absence of provenance is itself a signal — data introduced without protocol-level origin tracking evaluates as lowest quality.

### Decision

Implement `scp-core/provenance/` module. `DataProvenance` struct is attached automatically on cross-context data flows. Provenance quality is evaluable but policy decisions are agent-level. Chain depth is tracked and limited to prevent unbounded cross-context traversal.

### Rationale

- **Automatic attachment over manual tagging:** Agents should not need to remember to tag provenance. The protocol attaches it at tool interface boundaries and cross-context message boundaries. Manual tagging is error-prone and inconsistent.
- **Quality tiers over binary trust:** Provenance quality is a spectrum (§7.7.2). `PersistentVerifiable` (source still verifiable) is stronger than `EphemeralKnownParties` (source keys destroyed, parties known) which is stronger than `NoProvenance` (unknown origin). Agents use quality in their trust evaluation.
- **Chain depth limit:** Unlimited cross-context hops create accountability laundering — data traverses enough contexts that its origin becomes meaningless. The protocol default of 3 hops bounds this.

### Implementation

- **Language:** Rust
- **Crate:** `scp-core`
- **Module:** `scp-core/provenance/`
- **Serialization:** MessagePack with `StoredValue<T>` version envelope (§17.5) when persisted.

### Dependencies

- **ADR-010 (Tool Invocation):** Provenance attaches at tool interface boundaries during cross-context calls.
- **ADR-011 (Event Log):** Provenance records are events in both source and target context logs.

### Acceptance Criteria

1. **Key types:**

```rust
/// Data provenance metadata (§7.7.1).
pub struct DataProvenance {
    pub source_context: ContextId,
    pub source_type: SourceType,
    pub counterparties: Vec<DID>,
    pub purpose: Option<String>,
    pub discovery_method: DiscoveryMethod,
    pub age: Duration,
    pub memory_scope: MemoryScope,
    pub chain_depth: u8,
    pub chain_path: Option<Vec<ContextId>>,
}

/// Reflects current data availability, not creation-time setting.
pub enum SourceType {
    Persistent,   // Source context still open and verifiable
    Ephemeral,    // Source context closed, keys destroyed
    Summary,      // Source context closed, summary available
}

pub enum DiscoveryMethod {
    SharedContext(ContextId),
    Registry(ContextId),
    None,
}

/// Provenance quality evaluation tiers (§7.7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProvenanceQuality {
    NoProvenance,
    EphemeralKnownParties,
    SummaryVerified,
    PersistentVerifiable,
}
```

2. **`attach_provenance(source_context, target_context, data) -> DataProvenance`**
   - Called automatically on cross-context tool interface calls.
   - Populates all fields from source context state.
   - Increments `chain_depth` from any existing provenance on the data.
   - Populates `counterparties` from source context membership roster at time of data flow.

3. **`check_chain_depth(provenance, max_depth) -> Result<(), ProvenanceError>`**
   - Protocol default max depth: 3 hops.
   - Call at max depth cannot trigger further cross-context calls.
   - Returns `ProvenanceError::ChainDepthExceeded` if limit reached.

4. **`evaluate_quality(provenance) -> ProvenanceQuality`**
   - `PersistentVerifiable`: source context is `Persistent` and still `Active`.
   - `SummaryVerified`: source context closed with `Summary` scope, summary verified.
   - `EphemeralKnownParties`: source context was `Ephemeral`, keys destroyed, but counterparties known.
   - `NoProvenance`: data introduced without protocol-level origin tracking.

5. **`update_source_type(provenance, source_context_state) -> DataProvenance`**
   - Source type reflects current operational state, not creation-time setting.
   - Called when source context state changes (e.g., context closes after provenance was generated).

6. **Chain path recording:**
   - `chain_path` optionally records ordered list of intermediary context IDs.
   - Populated when `chain_depth > 0`.

7. **Provenance serialization:**
   - Serialized via `StoredValue<T>` version envelope (§17.5) when persisted.
   - Recorded in both source and target contexts' event logs.

8. **No-provenance signal:**
   - Data introduced without protocol-level origin tracking evaluates as `ProvenanceQuality::NoProvenance`.
   - Agents are informed of absence — the evaluation function returns the lowest quality tier, not an error.

### Scope

**Files (~3):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `DataProvenance`, `SourceType`, `DiscoveryMethod`, `ProvenanceQuality`, re-exports |
| `attach.rs` | `attach_provenance`, `check_chain_depth`, chain path management |
| `evaluate.rs` | `evaluate_quality`, `update_source_type`, quality tier logic |

**Estimated functions:** ~10 public functions, ~5 internal helpers.

---

## ADR-020: Tool-Interface Discovery

**Status:** Decided

### Context

Spec §6.2.2 defines two-tier discovery: DID document capabilities (direct lookup, zero setup) and discovery contexts (searchable registries, community-operated). DID documents contain a `SCPCapabilities` service entry that lists an agent's capabilities — resolvable by anyone who knows the DID. Discovery contexts are standard SCP contexts with open join policies and standardized tool schemas for search, registration, and deregistration. Two-tier membership (§6.2.2B) separates writers (MLS members, bounded) from readers (DID-authenticated, unbounded).

### Decision

Implement `scp-core/discovery/` module. DID document capability resolution via did:dht (ADR-003). Discovery contexts as standard SCP contexts with standardized tool schemas. Two-tier membership: writer (MLS, bounded at 500) + reader (DID-authenticated, unbounded). SDK provides unified search that merges local cache, DID resolution, and discovery context queries.

### Rationale

- **Two-tier membership over MLS-only:** MLS groups have practical size limits (~500 members for acceptable performance). Discovery contexts may serve thousands of readers. Separating writers (who process registrations as MLS application messages) from readers (who query via tool endpoints without MLS join) scales discovery beyond MLS group limits.
- **DID document capabilities over central registry:** Any agent can publish capabilities in their DID document — zero setup, zero registration, zero dependency on discovery contexts. Discovery contexts add searchability for agents that don't know each other's DIDs.
- **Standard schemas as conventions, not mandates:** The `agent_search`, `agent_register`, `agent_deregister` schemas are conventions that discovery contexts follow for interoperability. Custom tools (reputation scoring, category browsing, geographic filtering) are allowed beyond the standard set.
- **Bootstrap defaults as DNS root analogues:** SDK ships with configurable default discovery context IDs, analogous to DNS root servers. Users can add custom discovery contexts. If defaults are unreachable, direct DID resolution still works.

### Implementation

- **Language:** Rust
- **Crate:** `scp-core`
- **Module:** `scp-core/discovery/`

### Dependencies

- **ADR-003 (DID):** DID document resolution for capability lookup. `SCPCapabilities` service extraction.
- **ADR-010 (Tool Registration/Invocation):** Discovery contexts use standard tool schemas. Registration/search are tool invocations.
- **ADR-008 (Context Lifecycle):** Discovery contexts are standard SCP contexts with specific configuration.

### Acceptance Criteria

1. **Key types:**

```rust
/// Capability entry from a DID document service array.
pub struct CapabilityEntry {
    pub did: DID,
    pub capabilities: Vec<String>,
    pub service_endpoints: Vec<String>,
    pub resolved_at: u64,
}

pub struct DiscoveryQuery {
    pub capability_filter: Option<Vec<String>>,
    pub keywords: Option<Vec<String>>,
    pub min_history: Option<Duration>,
}

pub struct DiscoveryResult {
    pub entries: Vec<DiscoveryResultEntry>,
    pub sources: Vec<ContextId>,
}

pub struct DiscoveryResultEntry {
    pub did: DID,
    pub capabilities: Vec<String>,
    pub behavioral_summary: Option<serde_json::Value>,
    pub provenance: DataProvenance,
    pub relevance_score: f64,
}

pub struct RegistrationEntry {
    pub did: DID,
    pub capabilities: Vec<String>,
    pub metadata: serde_json::Value,
    pub entry_id: String,
    pub registered_at: u64,
}

pub struct DiscoveryBootstrap {
    pub default_context_ids: Vec<ContextId>,
}
```

**Standard tool schemas (conventions, not mandates — per §6.2.2B):**

```
agent_search(query) -> { results: [{ did, capabilities, behavioral_summary }] }
agent_register(did, capabilities, metadata) -> { registered, entry_id }
agent_deregister(did) -> { removed }
```

2. **DID document capability resolution:**
   - `resolve_capabilities(did) -> Result<CapabilityEntry, DiscoveryError>`: Resolve DID via did:dht, extract `SCPCapabilities` from service array, cache in local contact index.

3. **Discovery context standard tools:**
   - `agent_search`, `agent_register`, `agent_deregister` implemented per schema.
   - Custom tools (reputation scoring, category browsing, geographic filtering) allowed beyond standard.

4. **Two-tier membership:**
   - Writer tier: MLS members, bounded at 500, process registrations as MLS application messages.
   - Reader tier: DID-authenticated, unbounded, query via tool endpoints without MLS join.

5. **Registration flow:**
   - Reader sends DID-signed request.
   - Writer verifies signature, records in event log as application message.
   - Registrant does NOT become MLS member.

6. **Self-service updates:**
   - Registered agents update entries via DID-authenticated requests to tool endpoints.
   - Writers verify DID matches entry owner before applying update.

7. **`unified_search(query, known_contexts) -> Result<DiscoveryResult, DiscoveryError>`**
   - Local contact cache (instant).
   - Each known discovery context (parallel tool calls).
   - Merge, deduplicate, rank results.
   - Returns results with provenance per entry.

8. **Bootstrap:**
   - SDK ships configurable default discovery context IDs.
   - Auto-query on first identity creation (opt-out).
   - Fallback to direct DID resolution + manual context ID sharing.

9. **Privacy:**
   - Registration opt-in per discovery context.
   - Metadata controlled per registry.
   - Withdrawable via `agent_deregister`.
   - Agent can publish different capability subsets to different registries.

10. **Consistency:**
    - All writes recorded in discovery context's Merkle event log (ADR-011).
    - Readers can request inclusion proofs to verify registration and audit registry integrity.

### Scope

**Files (~5):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `DiscoveryQuery`, `DiscoveryResult`, re-exports |
| `did_capabilities.rs` | `resolve_capabilities`, DID document `SCPCapabilities` extraction, local contact cache |
| `context.rs` | Discovery context standard tool implementations (`agent_search`, `agent_register`, `agent_deregister`) |
| `search.rs` | `unified_search`, result merging, deduplication, ranking |
| `bootstrap.rs` | `DiscoveryBootstrap`, default context configuration, auto-query logic |

**Estimated functions:** ~15 public functions, ~10 internal helpers.

---

## ADR-021: UniFFI Bridge Definitions

**Status:** Pending

### What This ADR Will Decide

The UniFFI UDL (Universal Definition Language) file that defines the shared FFI surface for Swift and Kotlin SDKs. The UDL specifies which Rust types, functions, and traits are exposed across the FFI boundary, their argument/return types, error handling, and async bridging.

### Blockers

- Phase 1-2 Rust crate public API must be designed and implemented. The UDL maps to concrete Rust types (`Identity`, `ContextHandle`, `MlsGroup`, etc.) that don't exist yet.
- ADR-013 (PyO3 bridge) establishes the FFI pattern — the UniFFI bridge should expose an equivalent surface.

### Required Inputs When Writing

- Final Rust public API types from `scp-core`, `scp-transport`, `scp-platform`.
- OpenMLS `StorageProvider` interaction patterns (how MLS state flows through FFI).
- Error type hierarchy as implemented (`ScpCoreError`, `TransportError`, `PlatformError`).
- Async function signatures (which operations are async, which are sync).

### References

- `scaffold/shared.md` — cross-language naming table, streaming types per language, conformance test framework.
- `scaffold/swift.md` — Swift-specific patterns (actor isolation, `CheckedContinuation` bridging, XCFramework build).
- `scaffold/kotlin.md` — Kotlin-specific patterns (coroutine bridging, JNA/JVM integration).
- `standards/rust.md` — FFI bridge is the sole `unsafe` exception.
- ADR-013/014 — PyO3 bridge as reference pattern (flat function surface, opaque types, async bridging).
- Target file: `crates/scp-ffi/uniffi/src/scp.udl`.

### Expected Decisions

- UDL type mapping for all public domain types.
- Async function bridging strategy (UniFFI supports async via polling futures).
- Error mapping (Rust `Result` -> Swift `throws` / Kotlin exceptions).
- Callback interface definitions for platform traits (`KeyCustody`, `PushProvider`, `Storage`).
- Which types are passed by value (data classes) vs by reference (opaque handles).

### Optimal Approach

Write after Phase 2 implementation stabilizes. Review the PyO3 bridge (ADR-013) surface and mirror it in UDL. Run UniFFI `bindgen` to verify Swift/Kotlin output compiles.

### Scope

`scp-ffi/uniffi/` — 1 UDL file, ~2 Rust source files.

---

## ADR-022: TypeScript SDK (Dual-Target Architecture)

**Status:** Pending

### What This ADR Will Decide

The TypeScript SDK architecture spanning two runtime targets: browser (WASM via `wasm-bindgen`) and Bun/Node (native addon via `napi-rs`). The ADR covers the internal bridge module that selects the correct backend at runtime, the public API surface, and the build/bundling pipeline.

### Blockers

- Phase 1-3 Rust crate design must be complete (FFI function signatures derive from public API).
- ADR-021 (UniFFI) informed by same Rust API — TypeScript follows same types/operations.
- WASM-specific constraints (no filesystem, no threads in main thread) may require API adjustments.

### Required Inputs When Writing

- Final Rust public API from `scp-core`, `scp-transport`, `scp-platform`.
- `wasm-bindgen` type limitations (which Rust types can cross WASM boundary).
- `napi-rs` async bridging patterns (`ThreadsafeFunction`, `AsyncTask`).
- Browser storage adapter design (wa-sqlite + OPFSCoopSyncVFS from §17.6).

### References

- `scaffold/typescript.md` — dual-target architecture, bridge selection logic, package structure, build configuration.
- `standards/typescript.md` — strict mode, Biome linter, ECMAScript Resource Management, vitest.
- `scaffold/shared.md` — cross-language naming, streaming types (`AsyncIterable`), conformance tests.
- ADR-013/014 — PyO3 bridge pattern (flat functions, opaque types, async bridging).
- `scaffold/rust.md` — `scp-ffi/wasm/` and `scp-ffi/napi/` crate layouts.

### Expected Decisions

- Bridge selection logic: how runtime detection works (browser vs Bun vs Node), fallback behavior.
- Public API surface: Identity, Context, Tools, Trust, EventLog, Transport, UCAN, MCP modules.
- Error mapping: Rust `Result` -> typed TypeScript exceptions (`ScpError` hierarchy from scaffold).
- Streaming: `AsyncIterable` for message streams, disposal via `Symbol.asyncDispose`.
- Build pipeline: tsup config for dual ESM/CJS output, wasm-pack for browser target, napi-rs for Node target.
- Browser-specific: WebCrypto for key operations, wa-sqlite for storage, IndexedDB fallback.

### Optimal Approach

Write after Phase 3 (Python SDK ships). Python SDK validates the FFI surface; TypeScript mirrors it with browser-specific adaptations. Build the WASM bridge first (narrower API surface due to WASM constraints), then napi bridge (can expose fuller API).

### Scope

`scp-ffi/wasm/`, `scp-ffi/napi/`, `bindings/typescript/` — ~10 files.
