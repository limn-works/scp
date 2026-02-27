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

**Status:** Decided

### Context

The Swift and Kotlin SDKs require a shared FFI surface to the Rust protocol engine. UniFFI (Mozilla's Uniform Foreign Function Interface) generates Swift and Kotlin bindings from a single definition, producing idiomatic code for both platforms from one source of truth. The bridge layer is the boundary between `scp-core`, `scp-transport`, and `scp-platform` (Rust) and the Swift/Kotlin worlds. It must expose the same logical API surface as the PyO3 bridge (ADR-013) without leaking Rust concepts across the FFI boundary, while bridging async runtimes (tokio on the Rust side, Swift concurrency and Kotlin coroutines on the consumer side).

UniFFI supports two definition approaches: UDL files (external interface definition) and proc-macros (inline Rust annotations). The PyO3 bridge (ADR-013) established the FFI pattern for this project: flat function surface, opaque types for crypto state, async bridging, and a unified error hierarchy. The UniFFI bridge mirrors that surface for Swift and Kotlin.

### Decision

Implement the FFI bridge as the `scp-ffi/uniffi/` crate using UniFFI proc-macros (`#[uniffi::export]`) as the primary definition approach, with a UDL file (`scp.udl`) as a supplementary definition for callback interfaces and complex type mappings that proc-macros cannot express. The bridge exposes a flat set of exported functions and object interfaces that map directly to scp-core's public API — mirroring the PyO3 bridge surface (ADR-013). Async functions use UniFFI's native async support (`async fn` in `#[uniffi::export]`) to bridge Rust futures (tokio) to Swift async/await and Kotlin suspend functions. Rust `Result<T, E>` types are mapped to Swift `throws` and Kotlin exceptions via a unified `ScpError` enum. All SCP domain types are exposed as either opaque object interfaces (for types holding crypto state) or record/enum value types (for pure data). Platform-specific traits (`KeyCustody`, `PushProvider`, `Storage`) are exposed as UniFFI callback interfaces, allowing Swift and Kotlin implementations to be injected into the Rust engine.

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
- **Crate:** `scp-ffi/uniffi` (workspace member)
- **UDL file:** `crates/scp-ffi/uniffi/src/scp.udl` — callback interface definitions and supplementary type mappings
- **Build output:**
  - Swift: `ScpBindings.swift` — imported by the `SCP` Swift package (bindings/swift/)
  - Kotlin: `NativeLib.kt` — imported by the `scp-sdk-kotlin` module (bindings/kotlin/)
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
- **ADR-006 (Platform Abstraction):** Platform traits (`KeyCustody`, `PushProvider`, `Storage`, `AttestationProvider`) are exposed as callback interfaces. Swift implementations use Secure Enclave/Keychain/APNs; Kotlin implementations use Android Keystore/SharedPreferences/FCM.

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

   - `identity_create(custody) -> Identity` — creates a new DID identity. `custody` is a string: `"platform"`, `"in_memory"`.
   - `identity_load(did) -> Identity` — loads an existing identity from storage.
   - `identity_resolve(did) -> DIDDocument` — resolves a DID to its document.
   - `Identity` is an opaque object interface exposing: `did() -> String`, `custody_type() -> String`, `rotate_key() -> Identity`.

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
    callback interface KeyCustodyProvider {
        [Throws=ScpError]
        bytes sign(bytes message);

        [Throws=ScpError]
        bytes get_public_key();

        [Throws=ScpError]
        void destroy_key(string key_id);
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

    callback interface MessageListener {
        void on_message(Message message);
        void on_error(ScpError error);
        void on_complete();
    };
    ```

    - `KeyCustodyProvider`: Swift implementation wraps Secure Enclave/Keychain; Kotlin implementation wraps Android Keystore.
    - `StorageProvider`: Swift implementation wraps Core Data / UserDefaults / file-based storage; Kotlin implementation wraps Room / SharedPreferences.
    - `PushProvider`: Swift implementation wraps APNs; Kotlin implementation wraps FCM.
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
    - Kotlin bindings are packaged into the `scp-sdk-kotlin` AAR/JAR with native libraries bundled as resources (scaffold/kotlin.md).
    - CI runs `uniffi-bindgen generate` and verifies that the generated Swift and Kotlin output compiles against the current Rust API.

### Scope

**Files (~4):**

| File | Purpose |
|------|---------|
| `scp-ffi/uniffi/Cargo.toml` | Crate manifest with `uniffi` dependency and build configuration |
| `scp-ffi/uniffi/src/lib.rs` | Crate root, `uniffi::setup_scaffolding!()`, tokio runtime init, re-exports of bridge modules |
| `scp-ffi/uniffi/src/bridge.rs` | All `#[uniffi::export]` function definitions, opaque object `impl` blocks, record/enum derive macros, `ScpError` definition, `From` conversions from scp-core errors |
| `scp-ffi/uniffi/src/scp.udl` | Supplementary UDL: callback interface definitions (`KeyCustodyProvider`, `StorageProvider`, `PushProvider`, `MessageListener`), any type mappings that require UDL |

**Estimated functions:** ~25-30 bridge functions, ~15-20 type definitions (records + enums + objects), ~10-15 conversion helpers, 4 callback interfaces.

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
