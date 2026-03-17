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

Spec §7 defines four layers of trust evaluation, from hardest (pure validation) to softest (pure judgment). Layer 1 (UCAN enforcement) was implemented in ADR-016. The trust engine implements Layers 2-4: participation validation (verifiable event logs), participation records, attestation verification, challenge-response, and consequence evaluation. The trust engine provides validated inputs for agent-level evaluation — it does not produce trust "scores."

### Decision

Implement `scp-core/trust/` module. Participation records are computed locally from event logs (not stored centrally) — any agent computes from accessible logs. Attestation verification follows the common envelope format (§7.4.1). Challenge-response protocol enables verification of testable capabilities. Consequence rules are declared at context creation and protocol-enforced. Trust evaluation is agent-level — the engine provides validated inputs, not decisions.

### Rationale

- **Agent-level evaluation over protocol scores:** Trust is contextual (protocol tenet). The engine provides verifiable facts (participation records, verified attestations, challenge results, consequence structures), and each agent's trust evaluation logic consumes these facts according to its own criteria. No universal trust score.
- **Local computation over central storage:** Participation records are derived from event logs that every member has. No central participation database. Two agents may compute different records from different event log views — this is correct behavior, not a bug.
- **Common attestation envelope:** Uniform structure for all attestation types (§7.4.1) enables generic verification logic and interoperable attestation exchange.
- **Declared consequence rules:** Consequences are part of the opt-in contract — visible before joining, protocol-enforced, verifiable. No hidden penalties.

### Implementation

- **Language:** Rust
- **Crate:** `scp-core`
- **Module:** `scp-core/trust/`
- **Dependencies:** `sha2` (hashing), `ed25519-dalek` (signature verification)

### Dependencies

- **ADR-011 (Event Log):** Participation records are derived from event log entries.
- **ADR-016 (UCAN):** Layer 1 enforcement. Trust engine operates on Layers 2-4.
- **ADR-009 (Roles/Capabilities):** Governance action types, role history.

### Acceptance Criteria

1. **Key types:**

```rust
/// Verifiable facts computed from context event logs.
pub struct ParticipationRecord {
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
    pub participation_record: ParticipationRecord,
    pub challenge_results: Vec<(ChallengeRequest, ChallengeResponse)>,
    pub consequence_structure: Vec<ConsequenceRule>,
    pub threshold_counts: HashMap<AttestationType, (u32, u32)>,  // (met, required)
}
```

2. **`compute_participation_record(event_log, subject_did) -> Result<ParticipationRecord, TrustError>`**
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
   - Computes participation record from event log.
   - Collects and verifies attestations from cache.
   - Collects challenge results with timestamps.
   - Collects consequence structure from context params.
   - Computes threshold counts per attestation type.
   - Returns the complete `TrustInput` struct for agent-level evaluation.

10. **ProtocolRepository integration:**
    - Cache verified attestations with TTL-based refresh.
    - Store revocation list state per context.
    - Persist challenge results with timestamps.

### Scope

**Files (~6):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `TrustInput`, re-exports |
| `participation.rs` | `ParticipationRecord`, `compute_participation_record` |
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

Implement TTL tracking and memory scope enforcement in `scp-core/context/`. TTL is tracked per-context via ProtocolRepository. Memory scope drives key destruction behavior on context close. Promotion requires unanimous member consent because it changes the opt-in contract. Broadcast contexts are restricted to `Full` scope only — MLS-based forward secrecy is unavailable in broadcast mode.

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
    /// Renamed from `None` to `OutOfBand` to avoid shadowing `Optional.none`
    /// in Swift bindings (issue #772). Wire format changed from `"None"` to
    /// `"OutOfBand"`; `#[serde(alias = "None")]` preserves backward
    /// compatibility for deserialization of existing data.
    OutOfBand,
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
    pub participation_summary: Option<serde_json::Value>,
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
agent_search(query) -> { results: [{ did, capabilities, participation_summary }] }
agent_register(did, capabilities, metadata) -> { registered, entry_id }
agent_deregister(did) -> { removed }
```

2. **DID document capability resolution:**
   - `resolve_capabilities(did) -> Result<CapabilityEntry, DiscoveryError>`: Resolve DID via did:dht, extract `SCPCapabilities` from service array, cache in local contact index. Resolution returns all verification methods including the optional `#agent` VM (ADR-039), enabling callers to determine whether a DID has agent delegation enabled.

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

**Status:** Decided

### Context

The Swift and Kotlin SDKs require a shared FFI surface to the Rust protocol engine. UniFFI (Mozilla's Uniform Foreign Function Interface) generates Swift and Kotlin bindings from a single definition, producing idiomatic code for both platforms from one source of truth. The bridge layer is the boundary between `scp-core`, `scp-transport`, and `scp-platform` (Rust) and the Swift/Kotlin worlds. It must expose the same logical API surface as the PyO3 bridge (ADR-013) without leaking Rust concepts across the FFI boundary, while bridging async runtimes (tokio on the Rust side, Swift concurrency and Kotlin coroutines on the consumer side).

UniFFI supports two definition approaches: UDL files (external interface definition) and proc-macros (inline Rust annotations). The PyO3 bridge (ADR-013) established the FFI pattern for this project: flat function surface, opaque types for crypto state, async bridging, and a unified error hierarchy. The UniFFI bridge mirrors that surface for Swift and Kotlin.

### Decision

Implement the FFI bridge as the `crates/scp-ffi/uniffi/` crate using UniFFI proc-macros (`#[uniffi::export]`) as the primary definition approach, with a UDL file (`scp.udl`) as a supplementary definition for callback interfaces and complex type mappings that proc-macros cannot express. The bridge exposes a flat set of exported functions and object interfaces that map directly to scp-core's public API — mirroring the PyO3 bridge surface (ADR-013). Async functions use UniFFI's native async support (`async fn` in `#[uniffi::export]`) to bridge Rust futures (tokio) to Swift async/await and Kotlin suspend functions. Rust `Result<T, E>` types are mapped to Swift `throws` and Kotlin exceptions via a unified `ScpError` enum. All SCP domain types are exposed as either opaque object interfaces (for types holding crypto state) or record/enum value types (for pure data). Platform-specific traits (`KeyCustody`, `PushProvider`, `Storage`) are exposed as UniFFI callback interfaces, allowing Swift and Kotlin implementations to be injected into the Rust engine.

### Rationale

- **UniFFI proc-macros over UDL-only:** Proc-macros (`#[uniffi::export]`) keep the FFI definition co-located with the Rust implementation, reducing drift between the bridge and the API it wraps. UDL files are supplementary for callback interfaces and advanced patterns that proc-macros do not support. This is the approach recommended by the UniFFI project for new codebases.
- **UniFFI over cbindgen/manual FFI:** UniFFI generates idiomatic Swift and Kotlin bindings (classes, enums, async functions, error types) from a single definition. cbindgen generates C headers requiring manual wrapper code in each target language. Manual FFI would mean maintaining two separate hand-written binding layers. UniFFI eliminates this duplication and the consistency bugs it creates.
- **UniFFI over SwiftBridgeModule/KotlinBridge custom solutions:** Project-specific bridge generators would require building and maintaining custom tooling. UniFFI is battle-tested (Firefox, Application Services, and the broader Mozilla ecosystem), actively maintained, and has established patterns for async bridging, error handling, and callback interfaces.
- **Flat function surface mirroring ADR-013:** The bridge layer is deliberately flat (no deep class hierarchies). Each exported function maps to one Rust function. The idiomatic Swift API (actors, `AsyncSequence`, property wrappers) and idiomatic Kotlin API (coroutines, `Flow`, extension functions) are built in the pure language wrapper layers (Swift SDK, Kotlin SDK), not in the FFI bridge. This keeps the bridge thin and testable, matching the ADR-013 pattern where PyO3 exposes flat functions and the Python SDK wraps them.
- **Opaque objects for crypto state, records for data:** SCP types like `Identity`, `ContextHandle`, and transport connections hold crypto state (MLS group secrets, signing keys, session keys) that must not be serialized across the FFI boundary. They are exposed as opaque UniFFI objects with method accessors. Pure data types (`Message`, `ToolDefinition`, `ContextParams`) are exposed as UniFFI records (value types), which become Swift structs and Kotlin data classes.
- **Callback interfaces for platform injection:** `KeyCustody`, `PushProvider`, and `Storage` traits require platform-specific implementations (Secure Enclave on iOS, Android Keystore on Android, APNs vs FCM). UniFFI callback interfaces allow Swift and Kotlin code to implement these traits, which are then called from Rust. This preserves the dependency inversion architecture (ADR-006) across the FFI boundary.
- **Native async over blocking wrappers:** UniFFI supports `async fn` in exported interfaces, generating Swift `async` functions and Kotlin `suspend` functions. This eliminates the need for blocking wrappers with `Dispatchers.IO` (as described in scaffold/kotlin.md as the fallback pattern). The Rust tokio runtime runs in background threads; UniFFI's async machinery bridges between the runtimes.

### Implementation

- **Language:** Rust (UniFFI proc-macros + UDL) generating Swift and Kotlin bindings
- **Libraries:** `uniffi` (latest stable), `tokio` (async runtime)
- **Crate:** `crates/scp-ffi/uniffi` (workspace member)
- **UDL file:** `crates/scp-ffi/uniffi/src/scp.udl` — callback interface definitions and supplementary type mappings
- **Build output:**
  - Swift: `ScpBindings.swift` — imported by the `SCP` Swift package (bindings/swift/)
  - Kotlin: `NativeLib.kt` — imported by the `scp-kt` module (bindings/kotlin/)
  - C headers + module map for XCFramework packaging
- **Async runtime:** A single tokio `Runtime` is created at library initialization (via `uniffi::setup_scaffolding!()` init hook) and stored in a `OnceLock<Runtime>`. All async bridge functions run on this runtime. Runtime shutdown occurs on library unload with a 5-second grace period for in-flight tasks.
- **Platform libraries:** The Rust shared library is compiled for each target:
  - iOS: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios` (combined into XCFramework per scaffold/swift.md)
  - macOS: `aarch64-apple-darwin`, `x86_64-apple-darwin` (universal2 fat library)
  - Android: `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android` (bundled in AAR per scaffold/kotlin.md)
  - Desktop: Linux (`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`), macOS (universal2), Windows (`x86_64-pc-windows-msvc`) for JVM/desktop Kotlin

### Dependencies

- **All Phase 1 ADRs (ADR-001 through ADR-007):** The bridge exposes MLS operations, envelope creation, DID identity, transport, sender keys, and platform adapters to Swift and Kotlin.
- **All Phase 2 ADRs (ADR-008 through ADR-012):** The bridge exposes context lifecycle, role/UCAN enforcement, tool registration/invocation, event log queries, and multi-transport routing to Swift and Kotlin.
- **ADR-013 (PyO3 Bridge):** Establishes the FFI pattern. The UniFFI bridge mirrors the same logical API surface: same function set, same type categories (opaque vs value), same error hierarchy. ADR-013 is the reference implementation; ADR-021 must expose an equivalent surface.
- **ADR-006 (Platform Abstraction):** Platform traits (`KeyCustody`, `PushProvider`, `Storage`, `DeviceAttestationProvider`) are exposed as callback interfaces. Swift implementations use Keychain/APNs/DCAppAttestService; Kotlin implementations use Android Keystore/SharedPreferences/FCM/Play Integrity.

### Acceptance Criteria

1. **Tokio runtime initialization:**
   - A tokio `Runtime` is created once at library initialization via `uniffi::setup_scaffolding!()` init hook.
   - The runtime is multi-threaded (default thread count) and stored in a `OnceLock<Runtime>`.
   - All async bridge functions use UniFFI's native async support. The tokio runtime runs in background threads; async calls bridge automatically between the runtime and the caller's concurrency context (Swift structured concurrency / Kotlin coroutine dispatchers).
   - Runtime shutdown is handled on library unload. The `Runtime` is dropped, which waits for in-flight tasks to complete (with a 5-second timeout).

2. **Identity bridge functions:**

   ```rust
   #[uniffi::export]
   async fn identity_create(custody: String) -> Result<Arc<Identity>, ScpError> { ... }

   #[uniffi::export]
   async fn identity_load(did: String) -> Result<Arc<Identity>, ScpError> { ... }

   #[uniffi::export]
   async fn identity_resolve(did: String) -> Result<DIDDocument, ScpError> { ... }
   ```

   - `identity_create(custody) -> Identity` — creates a new DID identity with up to four keypairs (Identity Key, Active Signing Key, Pre-Rotation Key, and optionally Agent Signing Key per ADR-039). `custody` is a string: `"platform"`, `"in_memory"`.
   - `identity_load(did) -> Identity` — loads an existing identity from storage.
   - `identity_resolve(did) -> DIDDocument` — resolves a DID to its document. The returned `DIDDocument` includes all verification methods: `#0`, `#active`, and optionally `#agent` (ADR-039).
   - `Identity` is an opaque object interface exposing: `did() -> String`, `custody_type() -> String`, `rotateActiveKey() -> Identity`, `rotateAgentKey() -> Identity` (ADR-039 — separate rotation for `#active` and `#agent` keys).

3. **Context bridge functions:**

   ```rust
   #[uniffi::export]
   async fn context_create(
       identity: Arc<Identity>,
       params: ContextParams,
   ) -> Result<Arc<ContextHandle>, ScpError> { ... }

   #[uniffi::export]
   async fn context_join(
       handle: Arc<ContextHandle>,
       identity: Arc<Identity>,
   ) -> Result<(), ScpError> { ... }
   ```

   - `context_create(identity, params) -> ContextHandle` — creates a context. `params` is a UniFFI record with ceiling, roles, governance, TTL, memory_scope fields.
   - `context_join(handle, identity) -> void` — joins a context.
   - `context_leave(handle, identity) -> void` — leaves a context.
   - `context_close(handle, identity) -> void` — closes a context.
   - `context_send(handle, identity, payload) -> void` — sends a message.
   - `context_subscribe(handle, listener) -> void` — registers a callback interface for incoming messages (UniFFI callback; the Swift/Kotlin SDK layers convert this to `AsyncSequence` / `Flow<Message>` respectively).
   - `ContextHandle` is an opaque object interface exposing: `context_id() -> String`, `state() -> String`.

4. **Tool bridge functions:**
   - `tool_register(handle, registration) -> String` — registers a tool (returns tool ID).
   - `tool_invoke(handle, tool_id, input_json, identity) -> String` — invokes a tool (returns JSON string output).
   - `tool_verify(handle, tool_id) -> ToolVerificationResult` — verifies a tool against test vectors.

5. **Transport bridge functions:**
   - `transport_connect(relay_url) -> void` — connects to an SCP relay.
   - `transport_disconnect() -> void` — disconnects from the current SCP relay. No-op in browser environments (WebSocket lifecycle managed externally per ADR-034).
   - `transport_status() -> TransportStatus` — returns transport connection status.

6. **UCAN bridge functions:**
   - `ucan_validate(handle, token, capability) -> void` — validates a UCAN token (throws on failure).
   - `ucan_mint(handle, member_did, capabilities) -> UcanToken` — mints UCAN tokens.
   - `ucan_revoke(handle, token_id) -> void` — revokes a UCAN token.

7. **Event log bridge functions:**
   - `event_log_query(handle, filter_json) -> Vec<Event>` — queries the context event log.
   - `event_log_verify(handle, claim_json) -> Proof` — verifies a claim against the event log.

8. **Error mapping:**

   ```rust
   #[derive(Debug, uniffi::Error)]
   pub enum ScpError {
       Identity { message: String, code: String },
       Context { message: String, code: String },
       Permission { message: String, code: String },
       Crypto { message: String, code: String },
       Transport { message: String, code: String },
       Tool { message: String, code: String },
       Validation { message: String, code: String },
   }
   ```

   - Every Rust error type from scp-core maps to a specific `ScpError` variant.
   - Error codes follow the `SCP-{CATEGORY}-{NUMBER}` format (sdk-common.md).
   - In Swift: `ScpError` becomes an `enum` conforming to `Error` with associated values (`message`, `code`). Functions that return `Result` generate Swift `throws` functions.
   - In Kotlin: `ScpError` becomes a sealed exception hierarchy rooted at `ScpException`. Functions that return `Result` throw the corresponding exception subclass.
   - Error messages include actionable detail (what failed, why, what to do).

9. **Type mapping — opaque objects (passed by reference, hold state):**

   | Rust type | UniFFI kind | Swift generated | Kotlin generated |
   |-----------|-------------|-----------------|------------------|
   | `Identity` | `#[uniffi::export] impl` (object) | `class Identity` | `class Identity` |
   | `ContextHandle` | `#[uniffi::export] impl` (object) | `class ContextHandle` | `class ContextHandle` |
   | `UcanToken` | `#[uniffi::export] impl` (object) | `class UcanToken` | `class UcanToken` |
   | `TransportManager` | `#[uniffi::export] impl` (object) | `class TransportManager` | `class TransportManager` |

   All opaque objects are wrapped in `Arc<T>` for thread-safe shared ownership across the FFI boundary. UniFFI handles `Arc` automatically — the generated Swift/Kotlin code manages reference counting.

10. **Type mapping — records (passed by value, pure data):**

    | Rust type | UniFFI kind | Swift generated | Kotlin generated |
    |-----------|-------------|-----------------|------------------|
    | `ContextParams` | `#[derive(uniffi::Record)]` | `struct ContextParams` | `data class ContextParams` |
    | `Message` | `#[derive(uniffi::Record)]` | `struct Message` | `data class Message` |
    | `DIDDocument` | `#[derive(uniffi::Record)]` | `struct DIDDocument` | `data class DIDDocument` |
    | `ToolDefinition` | `#[derive(uniffi::Record)]` | `struct ToolDefinition` | `data class ToolDefinition` |
    | `ToolVerificationResult` | `#[derive(uniffi::Record)]` | `struct ToolVerificationResult` | `data class ToolVerificationResult` |
    | `TransportStatus` | `#[derive(uniffi::Record)]` | `struct TransportStatus` | `data class TransportStatus` |
    | `Event` | `#[derive(uniffi::Record)]` | `struct Event` | `data class Event` |
    | `Proof` | `#[derive(uniffi::Record)]` | `struct Proof` | `data class Proof` |

11. **Type mapping — enums:**

    | Rust type | UniFFI kind | Swift generated | Kotlin generated |
    |-----------|-------------|-----------------|------------------|
    | `CustodyMethod` | `#[derive(uniffi::Enum)]` | `enum CustodyMethod` | `enum class CustodyMethod` |
    | `ContextState` | `#[derive(uniffi::Enum)]` | `enum ContextState` | `enum class ContextState` |
    | `MemoryScope` | `#[derive(uniffi::Enum)]` | `enum MemoryScope` | `enum class MemoryScope` |
    | `GovernanceModel` | `#[derive(uniffi::Enum)]` | `enum GovernanceModel` | `enum class GovernanceModel` |

12. **Callback interfaces (platform trait injection):**

    ```
    // In scp.udl (callback interfaces require UDL definition)
    //
    // All 7 KeyCustody trait methods are exposed (SCP-214). dh_agree,
    // derive_pseudonym, generate_keypair, and custody_type were added.
    // ADR-027 amendment: derive_pseudonym uses public key bytes as HMAC key
    // for cross-platform TEE determinism (hardware TEE cannot export private bytes).
    // identity_create_platform() accepts a KeyCustodyProvider and creates a
    // did:dht identity using it; the adapter must be retained on the Identity
    // handle struct for subsequent crypto operations (context creation, signing).
    callback interface KeyCustodyProvider {
        [Throws=ScpError]
        bytes sign(string key_id, bytes message);

        [Throws=ScpError]
        bytes get_public_key(string key_id);

        [Throws=ScpError]
        void destroy_key(string key_id);

        [Throws=ScpError]
        string generate_keypair(string key_type);

        [Throws=ScpError]
        bytes dh_agree(string key_id, bytes peer_public);

        // Returns [public_key_bytes(32) || key_id_utf8_bytes].
        // Algorithm: seed = HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym"),
        // Ed25519_keygen(seed[0..32]). Public key bytes used as HMAC key per ADR-027.
        [Throws=ScpError]
        bytes derive_pseudonym(string key_id, bytes context_id);

        // Returns "hardware", "software", or "in_memory". Sync, no I/O.
        string custody_type(string key_id);
    };

    callback interface StorageProvider {
        [Throws=ScpError]
        bytes? get(string key);

        [Throws=ScpError]
        void set(string key, bytes value);

        [Throws=ScpError]
        void delete(string key);

        [Throws=ScpError]
        sequence<string> list_keys(string prefix);
    };

    callback interface PushProvider {
        [Throws=ScpError]
        void register_for_push(string token);

        [Throws=ScpError]
        void send_push(string recipient_token, bytes payload);
    };

    callback interface DeviceAttestationProvider {
        [Throws=ScpError]
        bytes attest(bytes challenge, bytes device_id);

        [Throws=ScpError]
        bytes assert(bytes request_hash);
    };

    callback interface MessageListener {
        void on_message(Message message);
        void on_error(ScpError error);
        void on_complete();
    };
    ```

    - `KeyCustodyProvider`: Swift implementation wraps Keychain (Secure Enclave supports P-256 only; SCP uses Ed25519 — see ADR-025); Kotlin implementation wraps Android Keystore.
    - `StorageProvider`: Swift implementation wraps SQLCipher-encrypted SQLite with Keychain-protected key (ADR-025); Kotlin implementation wraps SQLCipher with Android Keystore-protected key (ADR-027).
    - `PushProvider`: Swift implementation wraps APNs; Kotlin implementation wraps FCM.
    - `DeviceAttestationProvider`: Swift implementation wraps `DCAppAttestService` (App Attest) on iOS/macOS; Kotlin implementation wraps Play Integrity API on Android. Used by ADR-025 (Apple Platform Adapter) and the Android adapter.
    - `MessageListener`: Callback for incoming message streams. The Swift SDK converts to `AsyncStream<Message>` via `AsyncStream.Continuation`; the Kotlin SDK converts to `Flow<Message>` via `callbackFlow`.

13. **Async bridging:**
    - All functions that perform I/O (network, storage, crypto operations) are declared `async` in the UniFFI export.
    - UniFFI generates Swift `async` functions (bridged via `CheckedContinuation`) and Kotlin `suspend` functions (bridged via coroutine integration).
    - The Rust tokio runtime executes the future; UniFFI's async scaffolding resumes the caller's async context on completion.
    - Sync accessors on opaque objects (e.g., `Identity.did()`, `ContextHandle.context_id()`) are non-async and return immediately.
    - Streaming (message receive) uses the `MessageListener` callback interface rather than async return, because UniFFI does not support returning `Stream` types. The Swift/Kotlin SDK wrapper layers convert the callback pattern to `AsyncSequence` / `Flow` respectively.

14. **Thread safety:**
    - All opaque objects are `Send + Sync` (guaranteed by `Arc` wrapping).
    - UniFFI callbacks execute on Rust tokio threads. Callback implementations must not assume any specific thread or dispatcher (sdk-common.md risk #2). UI-bound operations in callbacks must dispatch to the appropriate context (`MainActor.run {}` in Swift, `Dispatchers.Main` in Kotlin).
    - The generated binding code is safe for concurrent use from multiple Swift tasks / Kotlin coroutines.

15. **Build and distribution:**
    - `uniffi-bindgen generate` produces Swift and Kotlin source files from the proc-macro exports and UDL.
    - Swift bindings are packaged into the `SCP` XCFramework (scaffold/swift.md build process).
    - Kotlin bindings are packaged into the `scp-kt` AAR/JAR with native libraries bundled as resources (scaffold/kotlin.md).
    - CI runs `uniffi-bindgen generate` and verifies that the generated Swift and Kotlin output compiles against the current Rust API.

### Scope

**Files (~4):**

| File | Purpose |
|------|---------|
| `crates/scp-ffi/uniffi/Cargo.toml` | Crate manifest with `uniffi` dependency and build configuration |
| `crates/scp-ffi/uniffi/src/lib.rs` | Crate root, `uniffi::setup_scaffolding!()`, tokio runtime init, re-exports of bridge modules |
| `crates/scp-ffi/uniffi/src/bridge.rs` | All `#[uniffi::export]` function definitions, opaque object `impl` blocks, record/enum derive macros, `ScpError` definition, `From` conversions from scp-core errors |
| `crates/scp-ffi/uniffi/src/scp.udl` | Supplementary UDL: callback interface definitions (`KeyCustodyProvider`, `StorageProvider`, `PushProvider`, `DeviceAttestationProvider`, `MessageListener`), any type mappings that require UDL |

**Estimated functions:** ~25-30 bridge functions, ~15-20 type definitions (records + enums + objects), ~10-15 conversion helpers, 5 callback interfaces.

---

## ADR-022: TypeScript SDK (Dual-Target Architecture)

**Status:** Decided

### Context

The TypeScript SDK is the second most critical language binding for SCP after Python. The web and server-side JavaScript ecosystems are divided across two distinct runtime categories: browsers (Chrome, Firefox, Safari, WebView) and server-side runtimes (Bun, Node.js). These two environments have fundamentally different I/O models, available APIs, and binary addon support. Browsers can execute WebAssembly natively but cannot load native binary addons. Bun and Node.js can load native addons (`.node` files) with near-zero overhead but have no requirement to support WASM-only APIs.

A single TypeScript package (`@limn-works/scp-ts`) must serve both environments. Shipping two separate packages would fracture the ecosystem and force application developers to conditionally import different SDKs based on their deployment target — a violation of the builder tenet of simple, clean APIs. The dual-target architecture solves this by maintaining a single public package with unified types and identical method signatures, while dispatching to the correct FFI bridge at runtime.

The ADR-013 PyO3 bridge and ADR-021 UniFFI bridge established the project-wide FFI pattern: flat function surface, opaque types for crypto state, async bridging, unified error hierarchy. The TypeScript SDK follows the same logical pattern adapted for the JavaScript ecosystem (Promises instead of coroutines, `AsyncIterable` instead of generators, `Symbol.asyncDispose` for resource management).

### What This ADR Will Decide

- The two FFI bridges (wasm-bindgen for browser, napi-rs for Bun/Node) and their Rust crate structure.
- Runtime detection logic in `internal/bridge.ts` — how the correct backend is selected at import time without top-level await.
- The public API surface for the `@limn-works/scp-ts` package: `Identity`, `Context`, `Tools`, `EventLog`, `Transport`, `UCAN`, `MCP` modules.
- Error mapping from Rust `Result<T, E>` to the TypeScript `ScpError` hierarchy.
- Streaming: `AsyncIterable<Message>` for message receive, `Symbol.asyncDispose` for resource lifecycle.
- Build pipeline: tsup for ESM/CJS bundles, wasm-pack for browser WASM, napi-rs CLI for native addon.
- Browser-specific platform adapters: WebCrypto for key operations, wa-sqlite (OPFS) for storage.
- Package structure and npm publishing: `@limn-works/scp-ts` (unified) + `@limn-works/scp-ts-napi-{platform}` optional platform dependencies.

### Decision

Implement the TypeScript SDK as two FFI bridge crates — `crates/scp-ffi/wasm` (wasm-bindgen) and `crates/scp-ffi/napi` (napi-rs) — with a unified TypeScript wrapper package at `bindings/typescript/` published as `@limn-works/scp-ts` on npm. The bridge crates are thin translation layers (zero protocol logic); the TypeScript wrapper layer builds the idiomatic API on top. A runtime detection module (`internal/bridge.ts`) selects the correct backend at package import time using synchronous environment checks, with no top-level await, to preserve CJS compatibility.

Both bridge crates expose the same flat function surface, mirroring the ADR-013 and ADR-021 patterns. All functions that perform I/O are async (Rust `Future` bridged to JS `Promise`). Message streaming uses a callback-to-`AsyncIterable` adapter in the TypeScript wrapper. `Context` and `Identity` implement `AsyncDisposable` via `Symbol.asyncDispose` for automatic resource cleanup.

### Rationale

- **Two bridges over one:** Browsers cannot load native `.node` addons — only WASM. Bun/Node can load native addons with no WASM overhead. A single WASM-only bridge would impose unnecessary overhead on Bun/Node servers; a native-only bridge would exclude browsers entirely. Two bridges behind a single public API is the only approach that serves both environments without compromise.
- **wasm-bindgen over Emscripten or manual WASM:** wasm-bindgen generates idiomatic TypeScript/JavaScript bindings with automatic type conversion, Promise integration via `wasm-bindgen-futures`, and zero manual glue code. Emscripten targets C and produces heavier output unsuited to a Rust codebase. Manual WASM bindings require hand-maintaining the entire JS/Rust boundary — maintenance cost grows linearly with the API surface.
- **napi-rs over node-bindgen or N-API manual bindings:** napi-rs provides macro-driven bindings (`#[napi]`), native async support via `ThreadsafeFunction` and `AsyncTask`, and a build CLI (`napi build`) that handles cross-compilation and binary publishing via optional platform-specific npm packages. node-bindgen is less actively maintained. Manual N-API requires hand-writing C glue. napi-rs is the Rust-Node community standard.
- **Single `@limn-works/scp-ts` package with optional platform dependencies:** Application code imports `@limn-works/scp-ts` unconditionally. The package internally detects the runtime environment and loads the appropriate bridge. For Bun/Node, native addon binaries are distributed as `@limn-works/scp-ts-napi-{platform}` optional dependencies (following the pattern established by napi-rs community packages like `@napi-rs/canvas`). The WASM bundle is included directly in the main package since it is a pure JS+WASM artifact that works in any bundler.
- **Flat function surface mirroring ADR-013:** The bridge crates are deliberately flat (no class hierarchies). Each exported function maps to one Rust function. The ergonomic TypeScript API (class methods, `AsyncIterable`, `Symbol.asyncDispose`) is built in the pure TypeScript wrapper layer (`bindings/typescript/src/`), not in the FFI bridge. This keeps the bridges thin and testable, exactly matching the ADR-013 pattern.
- **Runtime detection without top-level await:** CJS modules cannot use top-level await. Bridge selection must be synchronous at import time. The detection logic uses `typeof window`, `typeof process`, `process.versions.bun`, and `globalThis` checks — all synchronous. The WASM binary is loaded lazily on first use (via `initWasm()` called from the async constructors), so the synchronous import path never blocks.
- **`Symbol.asyncDispose` for resource management:** TypeScript 5.2+ and Bun natively support ECMAScript Explicit Resource Management. `await using ctx = await Context.create(...)` ensures `ctx.leave()` is called even on exception. This is the idiomatic TypeScript pattern for resources with cleanup obligations, matching the Python SDK's `async with` pattern.

### Implementation

**Language:** Rust (wasm-bindgen + napi-rs macros) + TypeScript 5.7+

**Rust crates:**

- `crates/scp-ffi/wasm/` — wasm-bindgen bridge, built with `wasm-pack`
- `crates/scp-ffi/napi/` — napi-rs bridge, built with `napi build`

**TypeScript package:** `bindings/typescript/` published as `@limn-works/scp-ts`

**Bridge crate: wasm-bindgen (`crates/scp-ffi/wasm/`)**

```
crates/scp-ffi/wasm/
  Cargo.toml          # [lib] crate-type = ["cdylib"], wasm-bindgen + wasm-bindgen-futures deps
  src/
    lib.rs            # #[wasm_bindgen] annotated functions, WasmIdentity, WasmContextHandle
```

- All exported functions use `#[wasm_bindgen]`.
- Async functions return `js_sys::Promise` via `wasm_bindgen_futures::future_to_promise`.
- Opaque handles (`WasmIdentity`, `WasmContextHandle`) are annotated `#[wasm_bindgen]` structs holding Rust state behind a `RefCell` or `Arc<Mutex<...>>`.
- Message streaming uses a JS callback passed into the subscribe function; the TypeScript bridge layer wraps this into an `AsyncIterable<Message>` via an internal queue.
- Browser key custody uses Web Crypto API (injected as a JS callback into the Rust bridge).
- Browser storage uses wa-sqlite (OPFS-backed SQLite): the `Storage` platform trait implementation is a JS object passed as a wasm-bindgen closure.
- `wasm-pack build --target bundler` produces `.wasm` + JS glue consumed by tsup.

**Bridge crate: napi-rs (`crates/scp-ffi/napi/`)**

```
crates/scp-ffi/napi/
  Cargo.toml          # [lib] crate-type = ["cdylib"], napi-rs + tokio deps
  src/
    lib.rs            # #[napi] annotated functions, NapiIdentity, NapiContextHandle
```

- All exported functions use `#[napi]` or `#[napi(constructor)]` annotations.
- Async functions are declared `async fn` and annotated with `#[napi]`. napi-rs generates `ThreadsafeFunction`-backed async bridges automatically, running the Rust future on the tokio runtime and resolving the returned JS `Promise` from any thread.
- A single tokio `Runtime` is created at module load via `napi::Task` init or a `OnceLock<Runtime>`, shared across all async calls.
- Opaque handles (`NapiIdentity`, `NapiContextHandle`) are `#[napi]` structs.
- Message streaming uses a `#[napi(ts_return_type = "AsyncIterable<Message>")]` generator function backed by a `tokio::sync::mpsc` channel converted to an `AsyncIterable` via napi-rs's `Generator` type.
- Key custody uses the OS keychain (delegated to `scp-platform`'s `KeyCustody` trait implementation).
- Storage uses `scp-platform`'s `Storage` trait backed by SQLite (bundled-sqlcipher per §17).
- `napi build --release` produces `scp-ts.{platform}.node` artifacts distributed as `@limn-works/scp-ts-napi-{platform}` optional dependencies.

**TypeScript wrapper layer (`bindings/typescript/src/`)**

```
src/
  index.ts              # Re-exports: Identity, Context, ScpError subtypes, types
  identity.ts           # Identity class — delegates to bridge
  context.ts            # Context class (AsyncDisposable) — delegates to bridge
  tools.ts              # ToolDefinition, TestVector interfaces
  trust.ts              # evaluateTrust(), TrustEvaluation
  event-log.ts          # EventLog class, Event, Proof, Checkpoint
  errors.ts             # ScpError hierarchy
  transport.ts          # TransportConfig, relay connection helpers
  types.ts              # Message, Provenance, Capability, ContextParams
  ucan.ts               # validate(), mint(), revoke(), delegate()
  mcp.ts                # serveMcp(), McpClient
  internal/
    native.ts           # napi-rs addon binding (Bun/Node)
    wasm.ts             # wasm-bindgen binding (browser) + initWasm()
    bridge.ts           # Runtime detection + unified bridge interface
```

**Runtime detection (`internal/bridge.ts`)**

Bridge selection is synchronous at import time. The WASM module is initialized lazily on first async call:

```typescript
// internal/bridge.ts

type Bridge = typeof import("./native.js") | typeof import("./wasm.js");

function detectBridge(): "native" | "wasm" {
  // Bun exposes process.versions.bun
  if (typeof process !== "undefined" && process.versions?.bun) return "native";
  // Node.js exposes process.versions.node but not bun
  if (typeof process !== "undefined" && process.versions?.node) return "native";
  // Browser or browser-like environment
  return "wasm";
}

export const BRIDGE_TARGET = detectBridge();

// Bridge is loaded lazily — import() at first use
let _bridge: Bridge | null = null;

export async function getBridge(): Promise<Bridge> {
  if (_bridge !== null) return _bridge;
  if (BRIDGE_TARGET === "native") {
    _bridge = await import("./native.js");
  } else {
    const wasm = await import("./wasm.js");
    await wasm.initWasm(); // one-time WASM initialization
    _bridge = wasm;
  }
  return _bridge;
}
```

Application code never imports from `internal/`. The public API classes (`Identity`, `Context`, etc.) call `getBridge()` internally on their async factory methods.

**Public API — `Identity`**

```typescript
// src/identity.ts
export class Identity {
  readonly did: string;
  readonly custodyType: string;

  private constructor(did: string, custodyType: string, private readonly _handle: unknown) {
    this.did = did;
    this.custodyType = custodyType;
  }

  static async create(options: { custody?: "platform" | "in_memory" } = {}): Promise<Identity> {
    const bridge = await getBridge();
    const handle = await bridge.identityCreate(options.custody ?? "platform");
    return new Identity(handle.did(), handle.custodyType(), handle);
  }

  static async load(did: string): Promise<Identity> {
    const bridge = await getBridge();
    const handle = await bridge.identityLoad(did);
    return new Identity(handle.did(), handle.custodyType(), handle);
  }

  static async resolve(did: string): Promise<DIDDocument> {
    const bridge = await getBridge();
    return bridge.identityResolve(did);
  }

  async rotateKey(): Promise<Identity> {
    const bridge = await getBridge();
    const handle = await bridge.identityRotateKey(this._handle);
    return new Identity(handle.did(), handle.custodyType(), handle);
  }
}
```

**Public API — `Context`**

```typescript
// src/context.ts
export class Context implements AsyncDisposable {
  readonly contextId: string;

  private constructor(contextId: string, private readonly _handle: unknown) {
    this.contextId = contextId;
  }

  static async create(identity: Identity, params: ContextParams): Promise<Context> {
    const bridge = await getBridge();
    const handle = await bridge.contextCreate(identity._handle, params);
    return new Context(handle.contextId(), handle);
  }

  static async join(handle: Context, identity: Identity): Promise<void> {
    const bridge = await getBridge();
    await bridge.contextJoin(handle._handle, identity._handle);
  }

  async send(payload: string | Uint8Array): Promise<void> {
    const bridge = await getBridge();
    await bridge.contextSend(this._handle, payload);
  }

  async *receive(): AsyncIterable<Message> {
    // Internal queue bridging the callback-based bridge to AsyncIterable
    const queue: Message[] = [];
    let resolve: (() => void) | null = null;
    let done = false;

    const bridge = await getBridge();
    bridge.contextSubscribe(this._handle, {
      onMessage: (msg: Message) => { if (!done) { queue.push(msg); resolve?.(); resolve = null; } },
      onError: (_err: ScpError) => { done = true; resolve?.(); resolve = null; },
      onComplete: () => { done = true; resolve?.(); resolve = null; },
    });

    try {
      while (!done || queue.length > 0) {
        if (queue.length === 0) {
          await new Promise<void>((r) => { resolve = r; });
        }
        const msg = queue.shift();
        if (msg !== undefined) yield msg;
      }
    } finally {
      if (!done) {
        done = true;
        queue.length = 0;
        bridge.contextUnsubscribe(this._handle);
      }
    }
  }

  async leave(): Promise<void> {
    const bridge = await getBridge();
    await bridge.contextLeave(this._handle);
  }

  async close(): Promise<void> {
    const bridge = await getBridge();
    await bridge.contextClose(this._handle);
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.leave();
  }
}
```

**Error hierarchy**

```typescript
// src/errors.ts
export class ScpError extends Error {
  constructor(
    message: string,
    readonly code: string, // e.g. "SCP-CTX-2001"
  ) {
    super(message);
    this.name = "ScpError";
  }
}

export class IdentityError extends ScpError { override name = "IdentityError" as const; }
export class ContextError extends ScpError { override name = "ContextError" as const; }
export class PermissionError extends ScpError { override name = "PermissionError" as const; }
export class CryptoError extends ScpError { override name = "CryptoError" as const; }
export class TransportError extends ScpError { override name = "TransportError" as const; }
export class ToolError extends ScpError { override name = "ToolError" as const; }
export class ValidationError extends ScpError { override name = "ValidationError" as const; }
```

Rust errors from both bridge crates are mapped to these classes via the bridge layer. Each bridge translates its native error type (wasm-bindgen `JsValue`, napi-rs `napi::Error`) into a structured `{ name, message, code }` object, which `internal/bridge.ts` converts to the appropriate `ScpError` subclass.

**Build pipeline**

1. **WASM bridge:** `wasm-pack build crates/scp-ffi/wasm --target bundler` — produces `pkg/scp_ffi_wasm.js` + `pkg/scp_ffi_wasm_bg.wasm`. The `.wasm` file is inlined or bundled by tsup.
2. **napi bridge:** `cd crates/scp-ffi/napi && napi build --release --platform` — produces `scp-ts.{os}-{arch}.node`. Cross-compilation via GitHub Actions matrix produces all platform binaries. Binaries are distributed as `@limn-works/scp-ts-napi-linux-x64-gnu`, `@limn-works/scp-ts-napi-darwin-arm64`, etc., declared as `optionalDependencies` in `@limn-works/scp-ts`'s package.json.
3. **TypeScript bundle:** `tsup src/index.ts --format esm,cjs --dts` — produces `dist/index.js`, `dist/index.cjs`, `dist/index.d.ts`.

**`package.json` structure**

```json
{
  "name": "@limn-works/scp-ts",
  "version": "0.1.0",
  "type": "module",
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "require": "./dist/index.cjs",
      "types": "./dist/index.d.ts"
    }
  },
  "files": ["dist/", "README.md", "LICENSE"],
  "scripts": {
    "build": "tsup",
    "check": "tsc --noEmit",
    "lint": "biome check src/ tests/",
    "format": "biome format --write src/ tests/",
    "test": "bun test"
  },
  "engines": { "node": ">=22", "bun": ">=1.0" },
  "optionalDependencies": {
    "@limn-works/scp-ts-napi-linux-x64-gnu": "0.1.0",
    "@limn-works/scp-ts-napi-linux-arm64-gnu": "0.1.0",
    "@limn-works/scp-ts-napi-darwin-x64": "0.1.0",
    "@limn-works/scp-ts-napi-darwin-arm64": "0.1.0",
    "@limn-works/scp-ts-napi-win32-x64-msvc": "0.1.0"
  },
  "devDependencies": {
    "typescript": "^5.7.0",
    "@biomejs/biome": "latest",
    "tsup": "latest"
  }
}
```

### Dependencies

- **All Phase 1 ADRs (ADR-001 through ADR-007):** Both FFI bridges expose MLS operations, envelope creation, DID identity, transport, sender keys, and platform adapters to TypeScript.
- **All Phase 2 ADRs (ADR-008 through ADR-012):** Both bridges expose context lifecycle, role/UCAN enforcement, tool registration/invocation, event log queries, and multi-transport routing to TypeScript.
- **All Phase 3 ADRs (ADR-013 through ADR-016):** The Python SDK validates the FFI surface and establishes the logical API shape that TypeScript mirrors. ADR-013 (PyO3) is the canonical reference for the flat-function FFI pattern; this ADR follows the same structure.
- **ADR-021 (UniFFI Bridge):** ADR-021 establishes the same logical API surface for Swift/Kotlin. The TypeScript bridge exposes the same function set, same type categories (opaque handles vs plain data records), and same error hierarchy. ADR-021 is the immediate predecessor ADR; the TypeScript implementation must expose an equivalent surface.
- **ADR-006 (Platform Abstraction):** Browser-specific platform adapters (WebCrypto for `KeyCustody`, wa-sqlite for `Storage`) are injected into the WASM bridge via wasm-bindgen closures. Node/Bun uses the `scp-platform` in-process implementations via the napi bridge.

### Acceptance Criteria

1. **Runtime detection:**
   - `BRIDGE_TARGET` is `"native"` in Bun and Node.js 22+ environments.
   - `BRIDGE_TARGET` is `"wasm"` in browser environments (Chrome, Firefox, Safari).
   - Bridge detection is synchronous — no top-level await — preserving CJS compatibility.
   - `getBridge()` returns the same initialized bridge instance on repeated calls (no re-initialization).

2. **Identity API:**
   ```typescript
   const identity = await Identity.create({ custody: "in_memory" });
   expect(identity.did).toMatch(/^did:dht:/);
   expect(identity.custodyType).toBe("in_memory");

   const loaded = await Identity.load(identity.did);
   expect(loaded.did).toBe(identity.did);

   const doc = await Identity.resolve(identity.did);
   expect(doc.did).toBe(identity.did);
   expect(doc.verificationMethods.length).toBeGreaterThan(0);
   ```
   - `Identity.create({ custody: "in_memory" })` returns an `Identity` with a `did:dht:` DID.
   - `Identity.load(did)` rehydrates an existing identity from storage.
   - `Identity.resolve(did)` returns a `DIDDocument` with at least two verification methods (`#0`, `#active`), and optionally `#agent` if agent delegation is configured (ADR-039).
   - `Identity.rotateActiveKey()` returns a new `Identity` with a rotated `#active` key.
   - `Identity.rotateAgentKey()` returns a new `Identity` with a rotated (or newly provisioned) `#agent` key (ADR-039).

3. **Context API:**
   ```typescript
   await using ctx = await Context.create(identity, {
     ceiling: ["messages:read", "messages:write"],
     memoryScope: "ephemeral",
   });
   expect(ctx.contextId).toMatch(/^scp:/);
   await ctx.send("hello");
   // Leaving and cleanup happen automatically via Symbol.asyncDispose
   ```
   - `Context.create(identity, params)` creates a context and returns a `Context` handle.
   - `Context.create` with invalid params (e.g., unknown capability in ceiling) throws `ValidationError`.
   - `ctx.send(payload)` sends a message without throwing.
   - `ctx.receive()` returns an `AsyncIterable<Message>` that yields incoming messages.
   - `await using ctx` triggers `ctx.leave()` on scope exit (tests via spy on `leave`).
   - `ctx.close()` terminates the context; subsequent `ctx.send()` throws `ContextError`.

4. **Tool API:**
   ```typescript
   const toolId = await ctx.invokeTool("tool-id", { input: "value" }, identity);
   ```
   - `ctx.invokeTool(toolId, input, identity)` invokes a registered tool and returns JSON output.
   - Invoking a non-existent tool throws `ToolError` with code `SCP-TOOL-6001`.
   - Tool registration: `await ctx.registerTool(toolDefinition)` returns a tool ID string.

5. **UCAN API:**
   ```typescript
   const token = await mintUcan(ctx, memberDid, ["messages:read"]);
   await validateUcan(ctx, token.encoded, "messages:read"); // does not throw
   await expect(validateUcan(ctx, token.encoded, "messages:write")).rejects.toThrow(PermissionError);
   await revokeUcan(ctx, token.id);
   ```
   - `mintUcan(ctx, did, capabilities)` returns a `UcanToken` with `.encoded: string` and `.id: string`.
   - `validateUcan(ctx, token, capability)` resolves on valid token, rejects with `PermissionError` on invalid.
   - `revokeUcan(ctx, tokenId)` revokes the token; subsequent validation throws `PermissionError`.

6. **EventLog API:**
   - `eventLog.query(filter)` returns `Event[]` matching the filter.
   - `eventLog.verify(claim)` returns a `Proof` with `.valid: boolean`.
   - `eventLog.checkpoint()` returns a `Checkpoint` with `.root: string` (Merkle root hex).

7. **Transport API:**
   - `transport.connect(relayUrl)` connects to an SCP relay; resolves on success, rejects with `TransportError` on failure.
   - `transport.status()` returns `{ connected: boolean; relayUrl: string | null }`.

8. **Error mapping:**
   - Every Rust error category maps to the corresponding TypeScript error subclass.
   - All thrown errors are instances of `ScpError` (i.e., `err instanceof ScpError` is `true`).
   - Error `code` follows the `SCP-{CATEGORY}-{NUMBER}` format (sdk-common.md).
   - Error messages are human-readable and actionable (what failed, why, what to do).
   - `CryptoError` messages contain no key material or internal crypto state.

9. **Type declarations:**
   - `dist/index.d.ts` is generated by tsup.
   - All public APIs have complete TypeScript type signatures.
   - No `any` types in public API surface (`noExplicitAny` enforced via Biome).
   - `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess` enabled in tsconfig.

10. **WASM bridge — browser-specific:**
    - `initWasm()` must be called (internally by `getBridge()`) before any bridge function is invoked.
    - Key custody in browser uses the Web Crypto API (`SubtleCrypto.generateKey`, `SubtleCrypto.sign`).
    - Storage in browser uses wa-sqlite backed by the Origin Private File System (OPFS). Falls back to IndexedDB-backed wa-sqlite if OPFS is unavailable (non-secure context or missing browser support).
    - The WASM binary (`scp_ffi_wasm_bg.wasm`) is fetched relative to the JS module URL; bundlers that inline assets will embed it at build time.

11. **napi bridge — Bun/Node-specific:**
    - The native addon is loaded via `require('@limn-works/scp-ts-napi-{platform}')`, resolved from `optionalDependencies`.
    - If the platform-specific package is not installed, `getBridge()` throws `TransportError` with code `SCP-TRANS-5001` and an actionable message indicating the missing package.
    - Async bridge functions run on a multi-threaded tokio runtime. The runtime is created once at addon load time via `OnceLock<Runtime>` and shared across all calls.
    - The tokio runtime is shut down cleanly when the Node.js process exits (via napi-rs cleanup hook).

12. **Streaming — `AsyncIterable<Message>`:**
    - `ctx.receive()` is a generator method returning `AsyncIterable<Message>`.
    - Messages are delivered in sequence order.
    - Calling `break` on the `for await...of` loop stops message delivery and releases internal queue resources.
    - Concurrent `for await...of` loops on the same `Context` are each independent iterables (fan-out).

13. **Build and CI:**
    - `bun run build` produces `dist/index.js`, `dist/index.cjs`, `dist/index.d.ts` without errors.
    - `wasm-pack build crates/scp-ffi/wasm --target bundler` succeeds without errors.
    - `napi build --release` in `crates/scp-ffi/napi/` produces a `.node` file for the current platform.
    - `bunx tsc --noEmit` passes with zero errors.
    - `bunx biome check src/ tests/` passes with zero errors.
    - `bun test` passes: all unit tests and conformance tests green.
    - CI matrix builds napi artifacts for Linux x64/arm64, macOS arm64/x64, Windows x64.

14. **Conformance:**
    - `tests/conformance/conformance.test.ts` loads cross-language JSON fixtures from `tests/conformance/` and passes all categories: identity, context, messaging, tools, UCAN, transport, event log, error handling.
    - Conformance pass rate is 100% in both Bun and Node.js 22 LTS environments.

15. **Publishing:**
    - `@limn-works/scp-ts` is published to npm with ESM + CJS bundles, type declarations, and WASM bundle.
    - `@limn-works/scp-ts-napi-{platform}` packages are published for each supported platform.
    - `package.json` `engines` field requires `node >= 22` and `bun >= 1.0`.
    - All packages are version-pinned to `scp-core` version (sdk-common.md §Versioning).

### Scope

**Rust crates (~2 files each):**

| File | Purpose |
|------|---------|
| `crates/scp-ffi/wasm/Cargo.toml` | Crate manifest: `[lib] crate-type = ["cdylib"]`, wasm-bindgen + wasm-bindgen-futures deps |
| `crates/scp-ffi/wasm/src/lib.rs` | All `#[wasm_bindgen]` exported functions and structs; `WasmIdentity`, `WasmContextHandle`; message callback types; error mapping from scp-core to `JsValue` |
| `crates/scp-ffi/napi/Cargo.toml` | Crate manifest: `[lib] crate-type = ["cdylib"]`, napi-rs + tokio deps |
| `crates/scp-ffi/napi/src/lib.rs` | All `#[napi]` exported functions and structs; `NapiIdentity`, `NapiContextHandle`; `ThreadsafeFunction`/Generator-based streaming; tokio `OnceLock<Runtime>` init; error mapping from scp-core to `napi::Error` |

**TypeScript package (~12 files):**

| File | Purpose |
|------|---------|
| `bindings/typescript/package.json` | Package manifest: `@limn-works/scp-ts`, exports map, optionalDependencies for napi platform packages |
| `bindings/typescript/tsconfig.json` | TypeScript config: strict, ESNext target, bundler module resolution, declaration output |
| `bindings/typescript/biome.json` | Biome linter + formatter config |
| `bindings/typescript/tsup.config.ts` | tsup bundler config: ESM + CJS output, dts, sourcemap |
| `bindings/typescript/src/internal/bridge.ts` | Runtime detection (`BRIDGE_TARGET`, `getBridge()`), bridge interface type, error constructor mapping |
| `bindings/typescript/src/internal/wasm.ts` | wasm-bindgen module import, `initWasm()`, WASM handle wrappers |
| `bindings/typescript/src/internal/native.ts` | napi-rs addon `require()`, native handle wrappers, platform package resolution |
| `bindings/typescript/src/identity.ts` | `Identity` class — delegates to bridge; `DIDDocument` type |
| `bindings/typescript/src/context.ts` | `Context` class (`AsyncDisposable`); `AsyncIterable<Message>` receive generator |
| `bindings/typescript/src/errors.ts` | `ScpError` hierarchy (7 subclasses) |
| `bindings/typescript/src/types.ts` | `ContextParams`, `Message`, `Provenance`, `Capability`, `ToolDefinition`, `UcanToken`, shared types |
| `bindings/typescript/src/index.ts` | Public re-exports |

**Test files (~8 files):**

| File | Purpose |
|------|---------|
| `bindings/typescript/tests/identity.test.ts` | Identity create, load, resolve, rotate |
| `bindings/typescript/tests/context.test.ts` | Context lifecycle, send/receive, disposal |
| `bindings/typescript/tests/tools.test.ts` | Tool registration and invocation |
| `bindings/typescript/tests/ucan.test.ts` | UCAN mint, validate, revoke, delegate |
| `bindings/typescript/tests/transport.test.ts` | Connect, status |
| `bindings/typescript/tests/event-log.test.ts` | Query, verify, checkpoint |
| `bindings/typescript/tests/mcp.test.ts` | MCP server and client |
| `bindings/typescript/tests/conformance/conformance.test.ts` | Cross-language conformance runner |

**Estimated functions:** ~25-30 bridge functions per crate (mirroring ADR-013), ~15 type definitions, ~10 TypeScript wrapper classes/interfaces.

---

## ADR-034: WASM Bridge Re-Implementation Strategy

**Status:** Decided

### Context

ADR-022 specifies a wasm-bindgen bridge crate (`crates/scp-ffi/wasm/`) that compiles scp-core to WebAssembly for browser environments. In practice, scp-core cannot be compiled to `wasm32-unknown-unknown` due to two hard dependencies:

1. **tokio multi-thread runtime.** scp-core uses `tokio::runtime::Runtime` with the multi-thread scheduler (required by PyO3 native async, MLS group operations, and transport concurrency). The `wasm32-unknown-unknown` target does not support `std::thread`, so `tokio::runtime::Builder::new_multi_thread()` fails to compile. While tokio offers a `current_thread` runtime that compiles to WASM, switching would require pervasive changes throughout scp-core and all FFI bridges, breaking the single-implementation invariant.

2. **OpenMLS dependencies.** ~~OpenMLS pulls in platform-specific crypto backends (RustCrypto or ring) that include assembly routines and C code incompatible with `wasm32-unknown-unknown`.~~ **Update (2026-03-15):** OpenMLS 0.8 with `default-features = false, features = ["js"]` compiles cleanly to `wasm32-unknown-unknown`. The `js` feature uses the RustCrypto backend with WASM-compatible randomness (`getrandom/js`). The WASM bridge now uses OpenMLS directly for MLS encryption (see `crates/scp-ffi/wasm/src/crypto/`). Wire's production WASM deployment validates this approach. The remaining blocker is tokio multi-thread (item 1), not OpenMLS.

These are not feature-flag-able constraints — they are structural incompatibilities between scp-core's architecture and the WASM compilation target.

### Decision

The WASM bridge (`crates/scp-ffi/wasm/`) uses **verbatim re-implementation** of scp-core's public API surface in WASM-compatible Rust. The re-implementation:

- Implements the same public API types and function signatures as the napi-rs bridge.
- Uses `wasm-bindgen-futures` for async bridging (single-threaded, cooperative scheduling on the browser event loop).
- Uses WebCrypto API (via `web-sys`) for non-MLS cryptographic operations (Ed25519, randomness). **Update (2026-03-15):** MLS encryption uses OpenMLS directly with `features = ["js"]` — no WebCrypto shim needed for MLS.
- Uses OpenMLS 0.8 with the `js` feature flag for MLS group encryption, compiled directly to WASM. The `OpenMlsRustCrypto` in-memory provider handles crypto and storage.
- Passes the same cross-language conformance test suite as all other bridges (JSON fixtures from `tests/conformance/`).

The re-implementation is NOT a fork — it is a second implementation of the same specification, verified against the same acceptance criteria.

### Alternatives Considered

1. **Feature-gating tokio to `current_thread`.** Would require pervasive `#[cfg(target_arch = "wasm32")]` annotations throughout scp-core, dual-testing every async code path, and breaking the "one implementation" invariant for the protocol engine. Rejected because the maintenance burden exceeds that of a separate WASM bridge.

2. **Extracting `scp-core-portable`.** A hypothetical refactoring that strips scp-core into a platform-agnostic core with no tokio or OpenMLS dependency. The remaining functionality would be too thin to be useful — most protocol logic requires crypto and async I/O. Rejected because the extraction boundary does not exist at a useful abstraction layer.

3. **Emscripten compilation.** Emscripten can compile C/C++ dependencies (ring, OpenMLS's C backend) to WASM, but produces significantly larger binaries, requires manual JavaScript glue, and does not integrate with wasm-bindgen's type system. Rejected because it trades one set of problems for a worse set.

### Risk Profile

**Primary risk: implementation drift.** The WASM bridge may diverge from scp-core's behavior over time as new features are added to scp-core but not mirrored in the WASM re-implementation. This is the same category of risk that any multi-implementation protocol faces.

### Mitigation

1. **`wasm_conformance.rs` test suite.** A dedicated conformance test module that exercises every public API function of the WASM bridge against the same JSON test fixtures used by the native bridge. Both bridges must produce identical outputs for identical inputs.

2. **Cross-language conformance in CI.** The `tests/conformance/conformance.test.ts` runner (ADR-022 acceptance criterion 14) executes the full conformance suite in both Bun (napi-rs bridge) and a browser environment (wasm-bindgen bridge). CI fails if either bridge produces different results.

3. **Shared type definitions.** The `@limn-works/scp-ts` TypeScript types are defined once in `bindings/typescript/src/types/` and used by both bridges. Type-level drift is caught by the TypeScript compiler.

4. **New feature checklist.** Every PR that adds a new scp-core public API function must include a corresponding WASM bridge implementation or a tracking issue. CI can enforce this via a bridge surface parity check script.

### Dependencies

- **ADR-022 (TypeScript SDK):** Defines the TypeScript wrapper layer that consumes both bridges.
- **ADR-006 (Platform Adapter):** The WASM bridge implements the `Storage` and `KeyCustody` traits using browser-native APIs (wa-sqlite, WebCrypto).

---

## ADR-041: Agent Capability Registry (URI Namespace and Protocol Registry)

**Status:** Decided

### Context

The protocol specifies agent capability metadata in §4.4 and challenge-response verification in §7.3.4. The existing implementation has two problems:

1. **Fragmented identifier space.** `ChallengeType` in `scp-core/trust/challenge.rs` defines three hardcoded enum variants (`PromptInjectionResistance`, `SchemaValidation`, `RateLimitCompliance`) plus `Custom(String)` — but there is no structure to custom strings, no namespace authority, and no way to distinguish protocol-defined capabilities from user-defined ones. `CapabilityEntry` in `scp-core/discovery/did_capabilities.rs` uses unstructured `Vec<String>` for capability names with the `scp:capabilities:` prefix for DID document service endpoints — a different format from `ChallengeType`. These two systems describe the same concept (agent capabilities) with incompatible identifiers.

2. **No anti-spoofing.** Any agent can declare any capability string in its DID document. There is no reserved namespace for protocol-defined capabilities, no mechanism to reject unknown protocol-scoped URIs, and no way to distinguish a self-attested claim from a challenge-verified capability at the identifier level.

The challenge suite standards open question (00-open-questions.md) identified these gaps. The design decision resolves them with a structured URI namespace, a signed protocol registry, and clear authority boundaries.

### Decision

Define a three-authority URI namespace for agent capabilities:

**1. Protocol-defined challenge capabilities (`scp:capability:*`):**

```
scp:capability:{kebab-case-name}/v{integer}
```

Reserved prefix. SDKs MUST reject any `scp:capability:*` URI not present in the signed protocol registry. Fixed structure: no deeper nesting. Capabilities are atomic — exact string equality for matching.

Initial protocol registry defines 28 challenge capabilities across 10 categories:

| Category | Capabilities |
|----------|-------------|
| Safety & Security | `prompt-injection-resistance/v1`, `content-safety/v1`, `privacy-compliance/v1`, `credential-handling/v1` |
| Schema & Protocol Compliance | `schema-validation/v1`, `tool-schema-compliance/v1`, `output-format-compliance/v1` |
| Behavioral Compliance | `rate-limit-compliance/v1`, `instruction-adherence/v1`, `context-policy-adherence/v1`, `graceful-degradation/v1` |
| Operational | `latency-compliance/v1` (param: `max_ms`), `idempotency/v1`, `multilingual/v1` (param: `languages`) |
| Spending / Commerce | `spending-compliance/v1`, `cost-awareness/v1` |
| Reasoning / Logic | `logical-reasoning/v1`, `mathematical-reasoning/v1` (param: `difficulty`), `causal-reasoning/v1` |
| Code | `code-generation/v1` (param: `languages`), `code-review/v1` |
| Recall / Fidelity | `context-recall/v1`, `instruction-retention/v1` |
| Bias / Fairness | `bias-resistance/v1`, `viewpoint-diversity/v1` |
| Factual / Hallucination | `factual-accuracy/v1`, `hallucination-resistance/v1`, `source-attribution/v1` |

**2. DID-scoped custom capabilities:**

```
did:{method}:{id}:capability:{kebab-case-name}/v{integer}
```

Anyone can define capabilities under their own DID. Authority is the definer's identity. Verifiers evaluate the capability based on who defined it — trust in the capability is trust in the definer.

**3. System capabilities (`scp:system:*`):**

```
scp:system:{kebab-case-name}
```

Protocol-level feature flags for node roles. Not challenge-testable — these describe what a node does, not what an agent can prove. Initial set: `mls-group-management`, `key-rotation`, `governance-participation`, `relay-operation`, `bridge-operation`.

**Anti-spoofing model:**

- Declaring a URI in a DID document = self-attested claim (anyone can do this).
- Having a signed `ChallengeVerification` record = challenge-verified (can't fake verifier's signature).
- `scp:capability:*` prefix is reserved. SDKs reject unknown `scp:capability:*` URIs at parse time.
- Custom capabilities use DID-scoped namespace — authority is the definer's identity.

### Rationale

- **Structured URIs over free-form strings:** Free-form strings (the `Custom(String)` approach) provide no authority boundary, no versioning, and no way to distinguish protocol-defined from user-defined capabilities. URI structure solves all three: the prefix identifies authority, `/v{N}` provides versioning, and kebab-case enforces naming consistency.
- **DID-scoped custom namespace over centralized registry:** A centralized registry (maintained by Limn or a standards body) would violate the "protocol requires no operator" tenet. DID-scoped custom capabilities are self-sovereign — anyone can define them under their own DID without permission from any authority.
- **SDK-enforced prefix reservation over social convention:** Social convention ("please don't use `scp:capability:*` for your own capabilities") is unenforceable. SDK-level rejection of unknown `scp:capability:*` URIs makes spoofing mechanically impossible for conformant implementations.
- **Versioned capabilities over unversioned:** Challenge suites will evolve as attack vectors and verification techniques improve. Version numbers enable breaking changes without invalidating existing verifications.
- **System capabilities as separate namespace:** System capabilities (`scp:system:*`) describe node roles, not agent behaviors. They are not challenge-testable. Mixing them with challenge capabilities would create confusion about what can and cannot be verified.

### Alternatives Considered

1. **Free-form strings with no namespace structure.** The current `Custom(String)` approach. No authority boundary, no versioning, no anti-spoofing. Anyone can claim any string. This is what the protocol had before this ADR. Rejected because it provides no mechanism to distinguish protocol-defined from user-defined capabilities, and no way to prevent capability impersonation.

2. **Centralized registry maintained by a standards body or Limn.** A single authority defines and maintains the canonical capability list. New capabilities require registry approval. Rejected because it violates the "protocol requires no operator" tenet and creates a bottleneck for ecosystem evolution. The DID-scoped namespace provides the same extensibility without central authority.

3. **Capability ontology (OWL/RDF).** Formal semantic web vocabulary for capability relationships (subsumption, composition, equivalence). Provides rich reasoning but adds enormous complexity. Rejected because SCP capabilities are atomic (exact string match) and do not require subsumption reasoning. The URI structure provides sufficient expressiveness for the protocol's needs.

### Consequences

- `ChallengeType` enum evolves to support URI-based matching: existing variants map to `scp:capability:*` URIs, and `Custom(String)` is replaced by URI-validated custom types.
- `CapabilityEntry` in `did_capabilities.rs` adopts the URI format for capability strings.
- Context admission requirements can reference specific capability URIs (e.g., "requires `scp:capability:prompt-injection-resistance/v1` challenge-verified").
- SDK implementations across all languages must include the protocol registry and reject unknown `scp:capability:*` URIs.
- The protocol registry is versioned and signed. Adding new `scp:capability:*` URIs requires a protocol version bump.
- DID-scoped custom capabilities enable ecosystem-driven extension without protocol changes.

### Dependencies

- **ADR-017 (Trust Engine):** Challenge-response protocol that verifies capabilities.
- **ADR-020 (Tool-Interface Discovery):** DID document capability advertising that uses the URI format.
- **ADR-003 (DID Creation):** DID-scoped custom capabilities require DID resolution.
- **ADR-008 (Context Lifecycle):** Context admission requirements reference capability URIs.

### Acceptance Criteria

1. **URI parser** validates `scp:capability:{kebab-case}/v{N}`, `did:{method}:{id}:capability:{kebab-case}/v{N}`, and `scp:system:{kebab-case}`. Rejects malformed URIs with specific error variants.

2. **Protocol registry** contains all 28 challenge capability URIs and 5 system capability URIs. Lookup by URI returns registry metadata (category, description, parameter schema). Unknown `scp:capability:*` URIs return `Err(UnknownProtocolCapability)`.

3. **`ChallengeType` unification:** existing `PromptInjectionResistance` maps to `scp:capability:prompt-injection-resistance/v1`, `SchemaValidation` maps to `scp:capability:schema-validation/v1`, `RateLimitCompliance` maps to `scp:capability:rate-limit-compliance/v1`. `Custom(String)` is replaced by `Uri(CapabilityUri)` which must be a valid DID-scoped or protocol-scoped URI.

4. **`CapabilityEntry` update:** `capabilities: Vec<String>` becomes `capabilities: Vec<CapabilityUri>` where `CapabilityUri` is the validated URI type. DID document service endpoint parsing validates URIs.

5. **SDK validation:** `validate_capability_uri(uri) -> Result<CapabilityUri, CapabilityError>` rejects unknown `scp:capability:*` URIs, accepts known protocol URIs and all valid DID-scoped URIs.

6. **Context admission integration:** admission requirements can specify `required_capabilities: Vec<(CapabilityUri, VerificationLevel)>` where `VerificationLevel` is `SelfAttested` or `ChallengeVerified`.

---

## ADR-043: Scope Registration as Handle Convention

**Status:** Decided

### Context

SCP's human-readable addressing system (§22) defines handle tools (`handle_register`, `handle_lookup`, `handle_deregister`) that map human-readable names to DIDs or context IDs within a context's handle registry. The addressing system also defines "scopes" — the part after `@` in addresses like `alice@cooking-community` — which currently resolve via a client-side mapping of scope names to context IDs (§22.3.2). There is no protocol-level mechanism to register, look up, or deregister scope-to-context mappings.

Scope registration is needed so that contexts can be discovered by human-readable names. For example, a user typing `alice@cooking-community` needs to resolve `cooking-community` to a context ID before they can resolve `alice` within that context's handle registry. This is a two-hop resolution: scope name to context ID, then handle name to DID.

The existing handle tools already support `HandleTarget::Context`, which maps a handle name to a context ID plus relay URLs. Scope registration is functionally identical to handle registration with two constraints: (1) the target must be a context, not an identity; (2) scope names must not contain dots, since dots are the syntactic discriminator between scope-based and domain-based resolution (§22.8.1).

### Decision

Scope registration is a **convention on handle tools**, not a parallel type system. Three scope tools — `scope_register`, `scope_lookup`, `scope_deregister` — are aliases that delegate to the corresponding handle tools with two constraints enforced at the tool boundary:

1. **Context-only targets.** `scope_register` rejects `HandleTarget::Identity`. Scope names map to contexts, not to individual DIDs. Identity resolution within a context uses handle tools directly.

2. **No dots in scope names.** `validate_scope_name()` enforces the charset `[a-z0-9-]` (matching §22.3.2 normalization output), max 64 characters, no leading or trailing hyphens. Dots are forbidden because the presence of a dot in the scope portion of an address is the syntactic discriminator that routes resolution to the domain path (§22.8.1). Underscores are excluded to match the normalization output of §22.3.2, which strips non-alphanumeric characters except hyphens.

Scope tools share all handle types: `HandleRegisterParams`, `HandleRegisterResult`, `HandleEntry`, `HandleTarget`, `HandleMetadata`, `HandleDeregisterParams`, `HandleDeregisterResult`, `HandleLookupParams`, `HandleLookupResult`, `HandleTypeFilter`. No new types are introduced. The scope tools reuse the same `HandleRegistry` instances — no separate `ScopeRegistry` is needed.

Separate tool names (`scope_*` vs `handle_*`) provide semantic separation at the API surface: scope tools are "the phone book for namespaces" (mapping scope names to context IDs), while handle tools are "the phone book for participants" (mapping names to DIDs or contexts within a single namespace). The separate names also provide a future divergence point — if scope registration eventually needs constraints that handle registration does not, the tool boundary is already in place.

**Authorization model.** Governance of the hosting context controls who can register scopes (who is a writer). This is the same authorization model as handle registration (§22.3.1). There is no protocol-level verification that the registrant has any relationship to the target context. This is a deliberate design choice — the same model as DNS, where registrars do not verify that the registrant owns the IP address a domain points to. See Security Considerations below.

**Resolution flow.** A context with scope tools functions as a scope registry — a "phone book for namespaces." The SDK ships with Limn's context ID in bootstrap defaults (§6.2.2B). The two-hop resolution:

```
1. bootstrap context → scope_lookup("cooking-community") → context ID + relay URLs
2. resolved context → handle_lookup("alice") → DID
```

Any context can host scope tools alongside any combination of other tools (agent tools, handle tools, app tools). There is no special "scope registry" context type — it is just a context that happens to have scope tools registered.

### Alternatives Considered

1. **Separate `ScopeRegistry` type system.** A parallel set of types — `ScopeEntry`, `ScopeTarget`, `ScopeRegisterParams`, `ScopeRegisterResult`, `ScopeLookupParams`, `ScopeLookupResult`, `ScopeDeregisterParams`, `ScopeDeregisterResult`, `ScopeMetadata`, `ScopeRegistry` — mirroring the handle types with the two constraints baked in. This would require ~10 new types in scp-core, ~12 new FFI bridge functions (3 per bridge x 4 bridges), and ~4 SDK wrapper implementations. All of this duplication enforces exactly two constraints (no dots, context-only). Rejected because the cost-to-constraint ratio is unacceptable — a convention on existing handle tools achieves the same result with zero new types.

2. **SDK-local-only scope mapping.** No protocol-level scope registration. Each SDK maintains a local map of scope names to context IDs, populated by bootstrap defaults and manual configuration. Rejected because this provides no protocol-level conflict detection (two contexts claiming the same scope name), no multi-registry resolution (checking multiple registries for the same scope), and no mechanism for contexts to advertise their scope names to the network.

### Rationale

- **Handles already support `HandleTarget::Context`.** The existing handle system can already map a name to a context ID with relay URLs. Scope registration is a subset of handle registration (context targets only, restricted charset). Adding a parallel system duplicates infrastructure for two constraints.
- **Separate tool names provide semantic clarity without type duplication.** Users and agents think of scope lookup ("find me the cooking community") differently from handle lookup ("find me Alice in the cooking community"). Separate tool names reflect this mental model. But the underlying data model is identical — a name that maps to a context ID.
- **Future divergence point.** If scope registration eventually needs features that handle registration does not (e.g., scope-specific metadata fields, different governance models, or multi-registry federation), the tool boundary is already in place. The convention can evolve into a distinct system without breaking the API surface.
- **DNS analogy.** DNS domain registration is a convention on top of the DNS record system — a domain name is a record that maps to an IP address, with constraints (registrar governance, TLD rules, conflict resolution). Scope registration is the same: a convention on handle records with constraints (context-only targets, no-dot names, registry governance).

### Security Considerations

#### 1. Scope-as-Open-Redirect

**Threat:** A writer in a scope registry registers `banking-app` pointing to a malicious context. Users resolving `banking-app` are directed to the attacker's context.

**Mitigations:**
- **(a) Governance controls writer access.** Curated registries (e.g., Limn's) select trusted writers. Only writers with the appropriate role and UCAN capabilities can call `scope_register`. Open-writer registries accept this risk as a governance tradeoff.
- **(b) Target context has independent access control.** A redirect does not grant access. The target context has its own cryptographic identity, MLS group, and governance. Being directed to a context is not the same as joining it — the user's SDK must still authenticate and be admitted.
- **(c) Resolution results carry provenance.** Every `HandleEntry` returned by `scope_lookup` carries metadata identifying which registry made the claim (`owner_did`, `registered_at`, `entry_id`). The `ResolutionPath` in `AddressResolution` (§22.8) identifies the resolution layer and source context. Consumers can inspect provenance before acting on a result.
- **(d) Multi-registry cross-verification.** The resolver can query multiple registries for the same scope name. If Limn's registry and an independent registry both map `banking-app` to the same context ID, confidence increases. If they disagree, the resolver surfaces both results with provenance, enabling the consumer to make an informed choice.

**Residual risk:** Open-writer registries accept scope-as-redirect as a governance tradeoff. Open registries SHOULD implement additional verification — for example, requiring the registrant to prove membership in the target context via a UCAN delegation chain from the target context's admin.

#### 2. No Target-Context Verification

**Threat:** The registrant has no verifiable relationship to the target context. Anyone can register `cooking-community` pointing to any context ID.

**Design rationale:** This is a deliberate choice. "Ownership" of a context is a governance concept, not protocol-verifiable. The context's creator is not necessarily its owner — ownership may transfer via governance actions (§5.9). Requiring target-context consent (e.g., a signed approval from the target context's admin) would:
- Require a protocol-level definition of "context owner" that does not exist.
- Create a circular dependency: you need the target context's cooperation to register a scope name for it, but the target context may not know or care about scope registries.
- Add a round-trip to every registration that most registries do not need.

**Governance opt-in:** Registries that want target-context verification CAN implement it as a governance policy: require the registrant to present a UCAN from the target context's admin granting `scope:register` capability. This is a registry-level policy decision, not a protocol requirement.

#### 3. relay_urls as Unvalidated Redirect Vector

**Threat:** `HandleTarget::Context { relay_urls }` accepts arbitrary URL strings. A malicious registration points to an attacker-controlled relay, enabling metadata surveillance or relay-level attacks.

**Mitigations:**
- **(a) `validate_relay_url` exists.** The FFI bridge validation layer (`validate.rs`) already implements `validate_relay_url`: scheme allowlist (`wss://`, `ws://` for development), no control characters, length limits. Each FFI bridge's `scope_register` wrapper validates relay URLs via `validate_relay_url` before calling the core function — the same pattern as handle registration.
- **(b) Transport security.** Relay connections use MLS encryption. A malicious relay can observe connection metadata (who connects, when, message sizes) but cannot decrypt message content. The relay is an untrusted pipe (protocol tenet: "Relays are untrusted dumb pipes").
- **(c) Relay URL validation is defense-in-depth.** It prevents obviously malicious URLs (javascript:, data:, non-URL strings) but cannot prevent a well-formed `wss://` URL from pointing to a hostile server.

**Residual risk:** Metadata surveillance via a hostile relay. Relay URL validation is defense-in-depth, not a complete mitigation. Users connecting to an unknown relay accept metadata exposure risk.

#### 4. DID from Request Body vs. Authenticated Session

**Threat:** `HandleDeregisterParams.did` is in the request body. A malicious caller supplies someone else's DID to deregister their scope entry.

**Mitigation:** The `did` field in deregister params is an assertion, not an authentication mechanism. The actual authentication is performed at the transport layer via DID-signed request envelopes (§22.3.1). Writers MUST:
1. Verify the DID-signed request signature using the requester's current DID document.
2. Compare the authenticated DID (from the signature) against the entry's `owner_did`.
3. Reject the request if the authenticated DID does not match the entry owner and the requester is not a context admin.

The `did` parameter makes the ownership check explicit in the API surface — it is visible in the tool schema rather than being an implicit side effect of transport authentication.

#### 5. Typosquatting Across Resolution Boundaries

**Threat:** `alice@limn` (scope-based, no dot) and `alice@limn.co` (domain-based, has dot) are different resolution paths that may resolve to different DIDs. A user may not distinguish between them.

**Mitigations:**
- **(a) Resolution path metadata.** The multi-path resolver returns results with explicit `ResolutionPath` metadata (§22.8). Consumers can distinguish scope-resolved results from domain-resolved results.
- **(b) SDK similarity warnings.** SDKs SHOULD warn when similar addresses resolve via different paths to different DIDs. For example, if both `alice@limn` and `alice@limn.co` are in the user's history and resolve to different DIDs, the SDK should surface this as a potential confusion risk.
- **(c) Petname disambiguation.** Petnames (§22.4) provide user-controlled disambiguation that overrides any ambiguity. Once the user assigns a petname, the ambiguous address is bypassed entirely.

**Classification:** UX hazard with SDK-level mitigations. Not a protocol-level vulnerability.

#### 6. Scope Name Squatting

**Threat:** First-come-first-served in open registries enables squatting on valuable scope names (`banking`, `government`, `healthcare`).

**Mitigations:**
- **(a) Curated registries.** Limn's model uses governance-controlled writer access, preventing arbitrary squatting. Registration requires approval from registry governance.
- **(b) Attestation-backed registration.** Governance can require registrants to prove external identity before claiming a scope name (e.g., linking a verified organization attestation to the registration request).
- **(c) Multi-registry coexistence.** Squatting one registry does not affect others. If an attacker squats `banking` in an open registry, a curated registry can independently assign `banking` to the legitimate context. The bootstrap config determines which registries are canonical for a given user or app — not the registries themselves.
- **(d) Bootstrap config is authoritative.** The user's or app's bootstrap configuration determines which registries are trusted and in what priority order. A squatted name in an untrusted registry has no effect if that registry is not in the user's bootstrap config.

**Classification:** Governance policy decision, not a protocol flaw. The protocol provides the mechanisms (multi-registry, governance, attestation) to mitigate squatting at the governance layer.

### Dependencies

- **ADR-020 (Tool-Interface Discovery):** Scope tools are registered in contexts that use the same discovery infrastructure.
- **ADR-010 (Tool Registration/Invocation):** Scope tools follow the standard tool registration and invocation protocol.
- **ADR-008 (Context Lifecycle):** The hosting context's governance controls scope registration authorization.
- **§22 (Human-Readable Addressing):** Scope tools extend the handle tool convention defined in §22.3.1.

### Acceptance Criteria

1. **Scope tool aliases.** Three tool constants: `TOOL_SCOPE_REGISTER`, `TOOL_SCOPE_LOOKUP`, `TOOL_SCOPE_DEREGISTER`. Each delegates to the corresponding handle tool with the constraints below.

2. **`validate_scope_name(name: &str) -> Result<(), AddressingError>`:** Validates that the name matches `[a-z0-9-]`, is 1-64 characters, and has no leading or trailing hyphens. Rejects names containing dots, underscores, or periods.

3. **`scope_register` rejects `HandleTarget::Identity`.** Returns an error if the target is not `HandleTarget::Context`. Validates the scope name via `validate_scope_name`. Delegates to `HandleRegistry::register()`.

4. **`scope_lookup` applies `type_filter: Context`.** Delegates to `HandleRegistry::lookup()` with `type_filter: Some(HandleTypeFilter::Context)`.

5. **`scope_deregister` delegates directly.** Calls `HandleRegistry::deregister()` with no additional constraints beyond scope name validation.

6. **No new types.** Scope tools reuse `HandleRegisterParams`, `HandleRegisterResult`, `HandleEntry`, `HandleTarget`, `HandleMetadata`, `HandleDeregisterParams`, `HandleDeregisterResult`, `HandleLookupParams`, `HandleLookupResult`, `HandleTypeFilter`.

7. **FFI bridges.** All four bridges (PyO3, NAPI, UniFFI, WASM) expose `scope_register`, `scope_lookup`, `scope_deregister` functions. The WASM bridge re-implements the constraint logic locally per ADR-034.

8. **Resolution integration.** Each FFI bridge's `address_resolve` function builds `known_contexts` from scope entries (entries with `HandleTarget::Context` targets) in addition to existing handle registry keys.
