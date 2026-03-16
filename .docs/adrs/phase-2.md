# Phase 2 Architecture Decision Records — Context + Transport

**Date:** February 22, 2026
**Phase goal:** Full context lifecycle over real transport. Two devices create contexts, exchange messages, invoke tools, verify event logs, and route across multiple relays.
**Deliverable:** Context state machine, UCAN-enforced roles, tool registration/invocation, verifiable event logs, multi-transport routing.
**Timeline:** Weeks 5-8
**Dependencies between ADRs:**

```
ADR-001 (MLS)      ADR-002 (Envelope)     ADR-005 (Transport Trait)
     \                  /       \                    |
      \                /         \                   |
       v              v           v                  |
      ADR-008 (Context) -----> ADR-011 (Event Log)   |
           |       \                                 |
           |        \                                |
           v         v                               v
      ADR-009 (Roles/UCAN)              ADR-012 (Multi-Transport)
           |
           v
      ADR-010 (Tools)
```

Build order: ADR-008 + ADR-011 (parallel, both depend on Phase 1) --> ADR-009 --> ADR-010 --> ADR-012 (independent of context internals, depends only on Phase 1 transport)

---

## ADR-008: Context Lifecycle State Machine

**Status:** Decided

### Context

The context is the fundamental interaction primitive in SCP. All communication, tool invocation, role assignment, and governance happens within a context. A context is backed by exactly one MLS group (spec section 9.7.1: MLS Group = SCP Context). The Context Manager is the central coordinator of the protocol engine (architecture.md section 2.2): it owns the state machine, membership tracking, role enforcement, tool routing, TTL management, and memory scope enforcement.

Phase 1 proved the crypto stack works (MLS groups, envelopes, transport). Phase 2 wraps that crypto in the context abstraction — the user-facing unit of interaction that carries governance, roles, tools, and lifecycle semantics on top of the raw encryption.

### Decision

Implement the context lifecycle as a five-state finite state machine in `scp-core/context/`. Each context transitions through: `Creating -> Active -> Closing -> Closed`, with an additional `Expired` terminal state reachable from `Active` when TTL elapses. The Context Manager owns all state transitions, and every transition is recorded in the context's verifiable event log (ADR-011). The MLS group is created during the `Creating -> Active` transition and destroyed during the `Closing -> Closed` transition.

### Rationale

- **Explicit state machine over implicit flags:** A context's lifecycle has well-defined phases with different permitted operations. An explicit state machine makes illegal state transitions unrepresentable. You cannot invoke a tool in a `Closed` context or add members to an `Expired` context — the state machine rejects the operation before it reaches the crypto layer.
- **Creating state:** Context creation is not atomic. The creator must: (1) define the context parameters (ceiling, roles, tools, TTL, memory scope, governance model), (2) create the MLS group, (3) generate the initial sender key (ADR-007), (4) publish to transport. The `Creating` state holds the context while these steps complete. If any step fails, the context never reaches `Active`.
- **Closing vs Closed:** Context closure is a multi-step process: (1) notify all members, (2) process final events, (3) generate summary if memory scope is `Summary`, (4) destroy MLS group state and sender keys. The `Closing` state gives members a window to process final events and verify the summary before keys are destroyed. Once `Closed`, key material is gone and content is physically unreadable (for ephemeral/summary scopes).
- **Expired as separate terminal state:** TTL expiry is distinct from intentional close. An expired context skips the cooperative closing window — TTL is a hard deadline (spec section 5.10). The governance model cannot override it. Extension requires unanimous consent from all members.
- **Every transition logged:** State transitions are protocol events recorded in the Merkle event log. This makes context lifecycle history verifiable — any member can prove when the context was created, when it closed, and who initiated each transition.

### Implementation

- **Language:** Rust
- **Crate:** `scp-core`
- **Module:** `scp-core/context/`
- **Async runtime:** tokio (TTL timers, MLS operations, transport)
- **State persistence:** Via `ProtocolRepository` (§17.4), which wraps the `scp-platform` `Storage` trait with typed domain methods. Context state is serialized and persisted on every transition so contexts survive process restarts. Key convention follows §17.3.

### Dependencies

- **ADR-001 (MLS):** Context creation creates an MLS group. Context closure destroys MLS group state. Member add/remove maps to MLS add_member/remove_member.
- **ADR-002 (Envelope):** All context messages are wrapped in SCP envelopes with per-context pseudonym routing.
- **ADR-007 (Sender Keys):** Context creation generates the creator's sender key. Member join triggers sender key bundle distribution. Context closure destroys all sender keys.
- **ADR-011 (Event Log):** Every state transition and context event is appended to the context's Merkle event log.

### Acceptance Criteria

1. **State machine definition:**

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextState {
    Creating,
    Active,
    Closing,
    Closed,
    Expired,
}
```

Valid transitions:
- `Creating -> Active` — MLS group formed, initial parameters committed, context published.
- `Active -> Closing` — Close initiated by admin (governance) or close-capable role.
- `Active -> Expired` — TTL elapsed. Automatic. No governance override.
- `Closing -> Closed` — All members processed final events, summary generated (if applicable), keys destroyed.

Invalid transitions (must return error):
- `Closed -> *` (terminal)
- `Expired -> *` (terminal)
- `Creating -> Closing` (never active, just drop)
- `Closing -> Active` (no re-opening)

2. **`create_context(params: ContextParams) -> Result<ContextHandle, ContextError>`**

   Context creation uses a **two-phase commit** pattern: validate all preconditions, then execute with rollback on failure.

   **Phase 1 — Validate (no side effects):**
   - Validates `ContextParams`: ceiling, roles, tools, TTL, memory scope, governance model.
   - If `template_id` is present, validates all params match the template definition exactly.
   - Validates the creator's identity is valid and the signing key is accessible.
   - Validates transport is connected and at least one relay is reachable.
   - If any validation fails, returns `ContextError` immediately. No state has been created.

   **Phase 2 — Execute (with ordered rollback):**

   Each step records its completion in a `CreationReceipt` struct. On failure at any step, all previously completed steps are rolled back in reverse order.

   ```rust
   struct CreationReceipt {
       mls_group: Option<MlsGroup>,       // None for Broadcast mode
       sender_key: Option<SenderKey>,      // Sender key (Encrypted) or broadcast key (Broadcast)
       event_log: Option<EventLog>,
       published: bool,
   }
   ```

   Steps:
   1. Transition state to `Creating`.
   2. If `mode == Encrypted`: Create MLS group via ADR-001 `create_group()`. If `mode == Broadcast`: Initialize creator's broadcast key (epoch 0) — no MLS group. On failure: drop `Creating` state, return error.
   3. If `mode == Encrypted`: Generate creator's sender key via ADR-007 `generate_sender_key()`. If `mode == Broadcast`: Broadcast key already initialized in step 2. On failure: destroy MLS group, return error.
   4. Initialize empty event log (ADR-011). On failure: destroy sender key, destroy MLS group, return error.
   5. Publish context to transport. On failure: drop event log, destroy sender key, destroy MLS group, return error.
   6. Transition state to `Active`.
   7. Append `ContextCreated` event to event log.
   8. Return `ContextHandle`.

   **Rollback guarantees:** After a failed `create_context` call, no MLS group state, no sender key material, and no event log state persists. The operation is atomic from the caller's perspective.

   **Transport publication failure:** If the context was partially published (e.g., sent to 1 of 3 relays before failure), the rollback issues `DELETE` requests for any published blobs. DELETE is best-effort (relays are untrusted), but since no MLS group state survives the rollback, any orphaned blobs on relays are encrypted with destroyed keys and cannot be used.

3. **`join_context(handle: &ContextHandle, key_package: KeyPackage) -> Result<(), ContextError>`**
   - Validates the joiner's key package.
   - Calls ADR-001 `add_member()` to add to MLS group.
   - Distributes sender key bundle to new member via ADR-007.
   - Assigns the joiner's role per the context's role configuration.
   - Issues UCAN tokens for the joiner's role capabilities (ADR-009).
   - Appends `MemberJoined` event to event log.

4. **`leave_context(handle: &ContextHandle, caller_did: &DID, member_did: &DID) -> Result<(), ContextError>`**
   - Authorization: self-removal (`caller_did == member_did`) is always allowed; otherwise caller must hold `MemberRemove` capability.
   - Calls ADR-001 `remove_member()` to remove from MLS group.
   - Removes member's sender key from all members' stores.
   - Appends `MemberLeft` event to event log.
   - If member count reaches zero, transitions to `Closing`.

5. **`close_context(handle: &ContextHandle, initiator_did: &DID) -> Result<(), ContextError>`**
   - Verifies initiator has close capability (admin role or governance-permitted).
   - Transitions state to `Closing`.
   - Sends close notification to all members.
   - If memory scope is `Summary`: triggers summary generation and verification window.
   - If memory scope is `Ephemeral` or `Summary`: schedules key destruction.
   - Appends `ContextClosing` event to event log.

6. **`finalize_close(handle: &ContextHandle) -> Result<(), ContextError>`**
   - Called after all members have processed the close notification.
   - Destroys MLS group state via ADR-001 `destroy_group()`.
   - Destroys all sender keys for this context.
   - Issues relay deletion requests for ephemeral/summary scope contexts (spec section 5.11).
   - Transitions state to `Closed`.
   - Appends `ContextClosed` event to event log (this is the final event).

7. **`handle_ttl_expiry(handle: &ContextHandle) -> Result<(), ContextError>`**
   - Triggered by TTL timer.
   - Transitions state directly from `Active` to `Expired`.
   - Sends expiry notification to all members.
   - Destroys MLS group state and sender keys per memory scope.
   - Appends `ContextExpired` event to event log.

8. **`send_message(handle: &ContextHandle, sender_did: &DID, payload: &[u8]) -> Result<(), ContextError>`**
   - Rejects if state is not `Active`.
   - Validates sender's UCAN for `messages:write` capability (ADR-009).
   - Assigns SCP sequence number (per-sender monotonic, spec section 9.8.5).
   - Encrypts with sender key (ADR-007), wraps in inner envelope (ADR-002), encrypts with MLS (ADR-001), wraps in outer envelope.
   - Sends via transport.
   - Appends `MessageSent` event to event log.

9. **`TTL timer management`**
   - On context creation with TTL: spawn a tokio timer task.
   - Timer fires at TTL expiry and calls `handle_ttl_expiry()`.
   - Timer is cancelled if context closes before TTL.
   - TTL extension (spec section 5.10): requires unanimous member consent. Resets timer.

10. **`ContextParams` struct:**

```rust
pub struct ContextParams {
    pub mode: ContextMode,               // Encrypted (default) or Broadcast (§5.14)
    pub ceiling: Vec<Capability>,        // Capability ceiling (bounded by ceiling_policy)
    pub ceiling_policy: CeilingPolicy,   // Whether the ceiling is immutable or governed (§5.3)
    pub promotion_policy: PromotionPolicy, // Whether context promotion is allowed (§5.10)
    pub roles: Vec<RoleDefinition>,      // Role definitions with permission sets
    pub tools: Vec<ToolRegistration>,    // Initial tool registrations
    pub ttl: Option<Duration>,           // Optional TTL
    pub memory_scope: MemoryScope,       // Ephemeral, Summary, or Full
    pub governance: GovernanceModel,     // Single-admin for Phase 2
    pub template_id: Option<TemplateId>, // Well-known template ID if created from template (§5.12)
}

/// Ceiling mutability policy. Declared at creation, immutable thereafter.
/// Determines whether the capability ceiling can be modified after context creation.
pub enum CeilingPolicy {
    /// Ceiling is fixed at creation. Any attempt to modify returns
    /// `ContextError::CeilingImmutable`. This is the default and the
    /// security-conservative choice — members see the ceiling before
    /// joining, and it cannot change (no bait-and-switch).
    Immutable,
    /// Ceiling can be modified through the context's governance model
    /// (admin, multi-sig, consensus). Changes are logged in the event
    /// log and visible to all members before taking effect. Members who
    /// joined under a narrower ceiling are notified and may leave before
    /// an expansion takes effect. See spec section 5.3.
    Governed,
}

/// Context promotion policy. Declared at creation, immutable thereafter.
/// Controls whether a context can be promoted (e.g., from ephemeral
/// to persistent, or from child to standalone).
pub enum PromotionPolicy {
    /// Context cannot be promoted. Immutable lifecycle constraints.
    NoPromotion,
    /// Context can be promoted through governance approval.
    /// Promotion conditions and requirements are governed by the
    /// context's governance model.
    Promotable,
}

/// Context processing mode. Immutable after creation.
pub enum ContextMode {
    Encrypted,  // MLS-backed, sender-side keys, full forward secrecy (default)
    Broadcast,  // Per-author broadcast keys, no MLS, mandatory subscriber registration (§5.14)
}

// Broadcast mode acceptance criteria (§5.14):
//
// When `mode == Broadcast`:
// - No MLS group is created. Context uses per-author AES-256-GCM broadcast keys
//   instead of MLS group keys.
// - Subscriber count is unlimited (no MLS group size bound).
// - The context's public `routing_id` is derived as `SHA-256(context_id)` —
//   deterministic and discoverable by any agent that knows the context_id.
// - Authors are bounded participants who hold `MessagesWrite` capability.
//   Each author maintains their own broadcast key with independent epoch rotation.
// - Subscribers hold `MessagesRead` capability and receive broadcast keys via
//   HPKE-wrapped key distribution (no MLS Welcome messages).
// - `create_context` skips MLS group creation (step 2) and instead initializes
//   the creator's broadcast key at epoch 0.
// - `join_context` for subscribers registers DID-authenticated subscription
//   without MLS add_member.
// - `send_message` encrypts with the author's current broadcast key, wraps in
//   `BroadcastEnvelope` (§5.14.5), and publishes to the public routing_id.
// - All other context lifecycle operations (close, expire, TTL, event log)
//   operate identically regardless of mode.

/// Well-known context templates (spec §5.12.1).
/// Templates are protocol constants — not user-extensible.
/// When present, all other ContextParams fields must match the template definition exactly.
pub enum TemplateId {
    BilateralEphemeral,   // Messaging-only, ephemeral, TTL required
    BilateralPersistent,  // Messaging-only, full memory, no TTL
    Coordination,         // Messaging + tools, summary memory, TTL required
    GroupDiscussion,      // Messaging + invites, full memory, optional TTL
    PublicBroadcast,      // Broadcast mode, open subscriber registration (§5.14)
    GatedBroadcast,       // Broadcast mode, UCAN-gated subscriber access (§5.14)
}

pub enum MemoryScope {
    Ephemeral,
    Summary,
    Full,
}
```

### Scope

**Files (~4-6):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `ContextHandle`, `ContextState` enum, re-exports |
| `state_machine.rs` | State transition logic, validation of legal transitions, transition event emission |
| `manager.rs` | `ContextManager` struct — create, join, leave, close, send. Coordinates between MLS, envelope, transport, event log |
| `params.rs` | `ContextParams`, `MemoryScope`, `GovernanceModel` (single-admin for Phase 2), `RoleDefinition`, `TemplateId` types |
| `templates.rs` | Well-known template definitions, template validation (params match template), template-based `ContextParams` construction |
| `ttl.rs` | TTL timer management — spawn, cancel, extend. tokio-based timer tasks |
| `membership.rs` | Member tracking, role assignment per member, member list queries, member count |
| `builder.rs` | `CreationReceipt`, two-phase commit logic, ordered rollback, precondition validation |

> **Note:** Context nesting (spec §5.13) is **not Phase 2 scope**. The `nesting.rs` module — parent-child relationship management, ceiling intersection validation, eligibility enforcement, lifecycle coupling, `ParentGovernanceConfig`, MLS `group_context` extension construction — will be introduced when nesting is implemented in a later phase. See the context nesting story in the PRD for scope and dependencies.

**Estimated functions:** ~20-25 public functions, ~15-20 internal helpers.

---

## ADR-009: Role Assignment and Capability Ceiling Enforcement

**Status:** Decided

### Context

SCP enforces a zero-trust capability model at Layer 1 (spec section 7.2): every action requires a valid UCAN capability token, verified mechanically. No action proceeds on identity or reputation alone. The capability ceiling is declared at context creation and is governed by the context's `CeilingPolicy` (ADR-008, spec section 5.3) — if `Immutable` (the default), the ceiling cannot change; if `Governed`, the ceiling can be modified through the context's governance model. The ceiling policy itself is immutable. Roles (spec section 5.5) define subsets of the ceiling that specific agents can exercise.

UCAN (User Controlled Authorization Networks) tokens provide the mechanism: per-agent, per-context, per-capability tokens with cryptographic delegation chains and independent revocability (spec section 7.2). The protocol validates UCAN signature chains, capability scoping, nonce uniqueness (spec section 9.5), and revocation status on every action.

### Decision

Implement UCAN-based capability enforcement in `scp-core/context/` and `scp-core/crypto/`. Every context operation — message send, tool invocation, member management, role change, governance action — requires a valid UCAN token. Tokens are issued at role assignment, scoped to the context and the role's permission set, and validated on every call. The ceiling is set at context creation; its mutability is determined by the `CeilingPolicy` declared at creation (ADR-008): `Immutable` (default, cannot change) or `Governed` (modifiable through governance). The ceiling policy itself is immutable.

### Rationale

- **UCAN over ACLs:** UCAN tokens are bearer tokens with cryptographic delegation chains. They are self-contained (no server roundtrip to check permissions), independently verifiable (any party can validate the chain), and independently revocable. ACLs require a central authority to check — UCAN requires only the token and the public keys in the chain.
- **Ceiling policy at creation:** The capability ceiling is part of the opt-in contract (spec section 5.7). Members see the ceiling and its mutability policy before joining. When `CeilingPolicy::Immutable` (the default for all well-known templates), the ceiling cannot change — preventing bait-and-switch. When `CeilingPolicy::Governed`, changes go through governance and members are notified before expansion takes effect (ADR-008). The ceiling policy itself is immutable — it cannot be changed after creation.
- **Per-action validation:** UCAN is validated on EVERY action, not just at context join. A token revoked mid-session takes effect immediately — the next action fails. This prevents permission drift and makes revocation instant.
- **Nonce uniqueness (spec section 9.5):** Every UCAN token includes a mandatory nonce. The SDK tracks seen nonces and rejects duplicates. This prevents token replay — a captured UCAN cannot be reused.
- **Role as token template:** Roles define which capabilities a member gets. When a member is assigned a role, the Context Manager mints UCAN tokens for each capability in the role's permission set, delegated from the context creator's authority. Role change = revoke old tokens + mint new tokens.

### Implementation

- **Language:** Rust
- **Library:** `rs-ucan` crate (or `ucan` crate — evaluate for UCAN 0.10+ spec compliance) [Note: replaced by native impl in scp-core/src/crypto/ucan/]
- **Crate:** `scp-core`
- **Modules:** `scp-core/context/roles.rs` (role definitions, assignment), `scp-core/crypto/ucan/` (UCAN wrapper, validation, revocation)
- **Nonce tracking:** In-memory set of seen nonces per context, persisted to storage.
- **Revocation:** Revocation list per context, distributed as MLS application messages.

### Dependencies

- **ADR-008 (Context):** Roles exist within contexts. Role assignment happens on member join. The capability ceiling is a context parameter.
- **ADR-003 (DID):** UCAN tokens are signed by DIDs. Delegation chains reference DIDs. Validation requires DID resolution for public key lookup.
- **rs-ucan library:** Third-party UCAN implementation. Must support UCAN 0.10+ spec with mandatory nonce field. [Note: replaced by native impl in scp-core/src/crypto/ucan/]

### Acceptance Criteria

1. **`CapabilityCeiling` type and enforcement:**

```rust
pub struct CapabilityCeiling {
    pub capabilities: HashSet<Capability>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Capability {
    MessagesRead,
    MessagesWrite,
    ToolInvoke(ToolId),           // Invoke a specific tool
    ToolInvokeAll,                // Invoke any registered tool
    ToolRegister,                 // Register new tools
    MemberInvite,                 // Invite new members
    MemberRemove,                 // Remove members
    RoleAssign,                   // Assign roles to members
    GovernancePropose,            // Propose governance actions
    GovernanceVote,               // Vote on governance proposals
    ContextClose,                 // Close the context
    ChildContextCreate,           // Create child contexts with this context as parent (§5.13)
    Custom(String),               // Context-specific custom capability
}
```

   **Mode-agnostic capabilities.** `MessagesRead` and `MessagesWrite` apply to both Encrypted and Broadcast modes. The abstract capability to read/write in a context is independent of the encryption pipeline — `ContextMode` determines processing, not authorization. No new capability variants are needed for broadcast mode.

   - Ceiling is set at context creation via `ContextParams.ceiling`.
   - Ceiling mutability is determined by `ContextParams.ceiling_policy` (ADR-008): `Immutable` (default) returns `ContextError::CeilingImmutable` on modification; `Governed` allows modification through the context's governance model.
   - Role permission sets are validated against the ceiling at role definition time. A role cannot grant capabilities outside the ceiling.

2. **`RoleDefinition` and built-in roles:**

```rust
pub struct RoleDefinition {
    pub name: String,
    pub capabilities: HashSet<Capability>,
}
```

   Built-in roles (always available):
   - `admin` — all capabilities in the ceiling.
   - `member` — `MessagesRead`, `MessagesWrite`, `ToolInvokeAll`.
   - `observer` — `MessagesRead` only.
   Custom roles are defined at context creation with arbitrary capability subsets of the ceiling.

   **Broadcast-specific roles.** Broadcast contexts (§5.14) add two roles that reuse existing primitives:
   - `author` — `MessagesWrite`, `MessagesRead`, `ToolInvokeAll`. Authors are bounded. Added via `RoleAssigned` event.
   - `subscriber` — `MessagesRead` only. In open broadcast contexts (`public-broadcast` template), `MessagesRead` is auto-granted on DID-authenticated registration, following the discovery context reader-tier pattern (§6.2.2B). In gated broadcast contexts (`gated-broadcast` template), `MessagesRead` requires an explicit admin-issued UCAN.

   The auto-grant subscriber pattern extends the discovery context two-tier model — it is not a new primitive.

3. **`assign_role(context: &ContextHandle, member_did: &DID, role: &str, assigner_did: &DID) -> Result<Vec<UcanToken>, ContextError>`**
   - Verifies assigner has `RoleAssign` capability (via UCAN validation).
   - Validates role exists in context's role definitions.
   - Mints UCAN tokens for each capability in the role's permission set.
   - Each token: `iss` = context creator DID, `aud` = member DID, `att` = `[{ "with": "scp:ctx:{context_id}/{capability}", "can": "invoke" }]`, `nnc` = unique nonce. The UCAN header includes `kid` (ADR-039) identifying the signing verification method (e.g., `"#active"` or `"#agent"`), enabling verifiers to resolve the correct public key from the issuer's DID document.
   - Distributes tokens to the member via MLS application message.
   - Revokes any previous tokens for this member (role change).
   - Appends `RoleAssigned` event to event log.
   - Returns the minted tokens.

4. **`validate_ucan(context: &ContextHandle, token: &UcanToken, required_capability: &Capability) -> Result<(), UcanError>`**

   Implement the **11-step UCAN validation pipeline** defined in ADR-016 (Phase 3) criterion 2. ADR-016 is the normative specification — implementations build the full 11-step pipeline from the start (it is a strict superset, not a future extension).

   The 11 steps:
   1. **Parse** — Decode JWT-format UCAN token; reject malformed tokens.
   2. **Signature verification** — Verify Ed25519 signature over `base64url(header).base64url(payload)`. If the header contains `kid` (ADR-039), resolve the correct public key from the issuer's DID document using that verification method ID (e.g., `"#active"`, `"#agent"`). If `kid` is absent, default to the issuer's `#active` verification method.
   3. **Chain verification** — For each proof CID in `prf`, resolve parent UCAN, verify its signature, verify parent's `aud` matches this token's `iss`. Recurse to root.
   4. **Root issuer** — Verify root token's `iss` is the context creator's DID.
   5. **Audience** — Verify token's `aud` matches the presenting agent's DID. Self-delegation (`iss == aud`) is valid when the token's `fct` contains `scp_key_scope` (ADR-039), indicating key-scope delegation (e.g., human delegates to their own agent key).
   6. **Capability match** — Verify token's `att` includes the `required_capability`.
   7. **Attenuation** — Verify each delegation narrows or preserves capabilities (never widens).
   8. **Ceiling** — Verify `required_capability` is within the context's immutable capability ceiling.
   9. **Nonce** — Validate format (`{unix_millis}-{hex16}`), validate freshness (±5 min), verify uniqueness, record in tracker.
   10. **Revocation** — Verify token CID is not in the context's revocation list.
   11. **Expiry** — Verify `exp > now` and `nbf <= now` (if present).

   Returns `Ok(())` if all 11 checks pass. Returns a specific `UcanError` variant indicating which check failed.

   **Phase 2 integration tests** exercise steps 1–2, 4–6, 8, 10–11 (the 8 steps that don't require delegation chain depth > 1). Phase 3 adds integration tests for steps 3, 7, 9.

5. **`revoke_ucan(context: &ContextHandle, token_id: &str, revoker_did: &DID) -> Result<(), UcanError>`**
   - Verifies revoker has authority (must be the token issuer or the context creator).
   - Adds token to the context's revocation list.
   - Distributes revocation as MLS application message to all members.
   - Appends `TokenRevoked` event to event log.

6. **`check_ceiling(ceiling: &CapabilityCeiling, capability: &Capability) -> bool`**
   - Returns true if the capability is within the ceiling.
   - Called as part of every UCAN validation.
   - Called at role definition time to validate role permission sets.

7. **`NonceTracker` struct:**

   ```rust
   pub struct NonceTracker {
       /// Map of nonce -> (first_seen_timestamp, token_expiry_timestamp).
       /// Both timestamps are Unix seconds.
       seen: HashMap<String, (u64, u64)>,
       context_id: ContextId,
   }
   ```

   **Nonce format, freshness, and replay:** ADR-016 (Phase 3) is the normative specification for nonce validation. Format: `{unix_millis_timestamp}-{16_random_bytes_hex}`. Freshness: ±5 minutes (§9.14 clock skew tolerance). Replay window: `max(token_expiry + 5 min, first_seen + 24 hours)`. Phase 2 implements the full nonce pipeline from ADR-016 — the validation is built once and is not phased. See ADR-016 criterion 6 for complete specification.

   **Pruning:** `prune()` removes entries where `now > max(token_expiry + 300, first_seen + 86400)`. Pruning runs every 1000 `check_and_record` calls or every 10 minutes, whichever comes first.

   - `check_and_record(nonce: &str, token_expiry: u64) -> Result<(), UcanError>`: Validates nonce format, validates freshness, returns `UcanError::NonceReused` if seen before, records `(now, token_expiry)` if new.
   - Backed by a `HashMap` per context, persisted to `scp-platform` Storage for crash recovery.

   **UCAN token expiry constraint (spec §9.5):** UCAN token `exp` MUST NOT exceed `now + 24 hours`. Tokens with `exp` beyond 24 hours from issuance are rejected at validation time.

### Scope

**Files (~3-4):**

| File | Purpose |
|------|---------|
| `scp-core/context/roles.rs` | `RoleDefinition`, `CapabilityCeiling`, `Capability` enum, built-in roles, `assign_role`, ceiling validation |
| `scp-core/crypto/ucan/mod.rs` | Module root, UCAN token types, re-exports |
| `scp-core/crypto/ucan/validate.rs` | `validate_ucan`, signature chain verification, capability matching, nonce checking, revocation checking |
| `scp-core/crypto/ucan/mint.rs` | `mint_ucan`, token creation, delegation chain construction, nonce generation |
| `scp-core/crypto/ucan/revoke.rs` | `revoke_ucan`, revocation list management, revocation distribution |

**Estimated functions:** ~12-15 public functions, ~8-10 internal helpers.

---

## ADR-010: Tool Registration and Invocation

**Status:** Decided

### Context

Tools are stateless functions scoped to a context (spec section 5.4). They are the protocol's answer to "bots" — tools cannot initiate, only respond. All agency flows through accountable agents. Tools have MCP-compatible JSON Schema interfaces (spec section 8.5), making them interoperable with existing MCP tooling. Every tool registration includes schema, implementation hash, test vectors, and operator DID — providing verifiable integrity (spec section 7.3.3).

Cross-context tool interfaces (spec section 6.2) allow structured interaction across context boundaries with bidirectional consent. The context governs the tool call, not the agent. Stateful tool sessions (spec section 6.2.1) enable multi-turn workflows via session IDs, TTLs, and per-call governance.

### Decision

Implement tool registration, invocation, and cross-context interfaces in `scp-core/context/tools/`. Tools are registered with full metadata (schema, hash, test vectors, operator DID), invoked through UCAN-enforced capability checks, and logged in the event log. Cross-context tool interfaces require explicit bidirectional opt-in at the context level. Stateful sessions are tracked by the tool's context with per-session TTLs.

### Rationale

- **MCP-compatible schema:** Tools use JSON Schema for input/output definitions (spec section 8.5). This means any MCP-compatible model can invoke SCP tools through the MCP adapter (architecture.md section 1.4) without modification. Schema compatibility is a requirement, not a nice-to-have.
- **Implementation hash for integrity:** The content-addressable hash of a tool's implementation is recorded at registration. Any change to the implementation produces a new hash, which is recorded as a mutation event in the event log. Silent tool modification is impossible — all members see the change (spec section 5.4).
- **Test vectors for continuous verification:** Any agent can call a tool with test vector inputs and verify outputs match (spec section 7.3.3). This enables threshold confidence: if N agents independently verify, the tool is almost certainly behaving correctly.
- **Context governs, not agent (spec section 6.2):** Cross-context tool calls are mediated by both contexts. An agent in Context A requests a tool call to Context B. Context A's governance decides whether to permit the outbound call. Context B's governance decides whether to permit the inbound call. The agent never directly touches the other context.
- **Stateful sessions (spec section 6.2.1):** Multi-turn workflows (scheduling, negotiation) need state across calls. Session state lives in the tool's context, not the caller's. Each call in a session is individually governed. Sessions have TTLs to prevent resource leaks.

### Implementation

- **Language:** Rust
- **Schema validation:** `jsonschema` crate for JSON Schema validation
- **Hashing:** SHA-256 via `sha2` crate for implementation hashes
- **Crate:** `scp-core`
- **Module:** `scp-core/context/tools/`
- **Session storage:** In-memory HashMap with TTL-based cleanup, keyed by session ID.

### Dependencies

- **ADR-008 (Context):** Tools are scoped to contexts. Tool registration is a context operation. Tool invocation requires an active context.
- **ADR-009 (Roles/UCAN):** Tool invocation requires `ToolInvoke(tool_id)` or `ToolInvokeAll` capability. Tool registration requires `ToolRegister` capability. Both are UCAN-validated.
- **ADR-011 (Event Log):** Tool registrations, mutations, and invocations are recorded in the event log.

### Acceptance Criteria

1. **`ToolRegistration` struct:**

```rust
pub struct ToolRegistration {
    pub tool_id: ToolId,
    pub name: String,
    pub description: String,
    pub schema: ToolSchema,              // MCP-compatible JSON Schema
    pub implementation_hash: [u8; 32],   // SHA-256 of implementation
    pub test_vectors: Vec<TestVector>,   // Known input-output pairs
    pub operator_did: DID,               // Accountable identity
}

pub struct ToolSchema {
    pub input_schema: serde_json::Value,   // JSON Schema for input
    pub output_schema: serde_json::Value,  // JSON Schema for output
}

pub struct TestVector {
    pub input: serde_json::Value,
    pub expected_output: serde_json::Value,
    pub description: String,
}
```

2. **`register_tool(context: &ContextHandle, registration: ToolRegistration, registrant_did: &DID) -> Result<ToolId, ToolError>`**
   - Validates registrant has `ToolRegister` capability via UCAN (ADR-009).
   - Validates input and output schemas are valid JSON Schema.
   - Validates implementation hash is 32 bytes.
   - Validates operator DID is resolvable.
   - Stores the tool registration in the context's tool registry.
   - Appends `ToolRegistered` event to event log with full registration metadata.
   - Returns the tool ID.

3. **`invoke_tool(context: &ContextHandle, tool_id: &ToolId, input: serde_json::Value, invoker_did: &DID) -> Result<serde_json::Value, ToolError>`**
   - Validates context state is `Active`.
   - Validates invoker has `ToolInvoke(tool_id)` or `ToolInvokeAll` capability via UCAN.
   - Validates input against the tool's input schema.
   - Calls the tool implementation.
   - Validates output against the tool's output schema.
   - Appends `ToolInvoked` event to event log (includes tool_id, invoker_did, input hash, output hash).
   - Returns the tool output.

**Tool execution lifecycle:**

Every tool invocation follows a defined lifecycle with explicit states, timeouts, and error handling.

```rust
/// A tool invocation request, sent as an MLS application message.
pub struct ToolRequest {
    pub request_id: String,          // UUID v4, unique per invocation
    pub tool_id: ToolId,
    pub invoker_did: DID,
    pub input: serde_json::Value,
    pub timeout_ms: u32,             // Caller-specified timeout (max: context ceiling, default: 30_000)
    pub session_id: Option<String>,  // For stateful sessions (§6.2.1)
    pub chain_depth: u8,             // Cross-context chain depth (0 for direct calls)
    pub timestamp: u64,
}

/// A tool invocation response, sent as an MLS application message.
pub struct ToolResponse {
    pub request_id: String,          // Matches the request
    pub status: ToolStatus,
    pub output: Option<serde_json::Value>,
    pub error: Option<ToolExecutionError>,
    pub execution_time_ms: u64,
    pub provenance: Provenance,
}

pub enum ToolStatus { Success, Error, Timeout, Cancelled }

pub struct ToolExecutionError {
    pub code: ToolErrorCode,
    pub message: String,
    pub retryable: bool,
}

pub enum ToolErrorCode {
    InputValidationFailed, OutputValidationFailed, ExecutionFailed,
    Timeout, Cancelled, RateLimited, ToolNotFound, PermissionDenied, InternalError,
}
```

**Timeout handling:**
- Every tool invocation has a timeout. Callers specify `timeout_ms` in the request (default: 30,000ms, maximum: configurable per-context, hard protocol maximum: 300,000ms / 5 minutes).
- The invoking SDK starts a timer on request submission. If no `ToolResponse` arrives before the timer fires, the SDK synthesizes a `ToolResponse` with `status: Timeout` and delivers it to the caller.
- Timeout is a client-side contract, not a server-side enforcement.

**Cancellation protocol:**
- The invoker MAY send a `ToolCancel { request_id, invoker_did, timestamp }` message referencing the `request_id`.
- On receiving `ToolCancel`, the tool's execution environment SHOULD terminate the invocation and respond with `status: Cancelled`.
- Cancellation is best-effort. If the tool responds with `Success` before the cancel is processed, the success response takes precedence.

**Error propagation:**
- Tool execution errors are returned in `ToolResponse.error`, not as protocol-level errors.
- Schema validation failures are caught by the SDK, not the tool. The SDK rejects invalid input before invoking the tool and rejects invalid output before delivering the response.
- The `retryable` field indicates whether the caller should attempt the invocation again.

**Event log recording:**
- `ToolRequest` and `ToolResponse` are both recorded as events in the context's event log (ADR-011).
- The event includes: `request_id`, `tool_id`, `invoker_did`, `status`, `execution_time_ms`, `SHA256(input)`, `SHA256(output)`. Full input/output is NOT recorded (may be large); only content hashes are stored.

4. **`update_tool(context: &ContextHandle, tool_id: &ToolId, new_registration: ToolRegistration, updater_did: &DID) -> Result<(), ToolError>`**
   - Validates updater is the tool's operator DID or has admin role.
   - Records old and new implementation hashes.
   - Updates the tool registration.
   - Appends `ToolUpdated` event to event log (includes old hash, new hash, all changed fields).
   - Tool mutations are visible to all context members.

5. **`verify_tool(context: &ContextHandle, tool_id: &ToolId) -> Result<ToolVerificationResult, ToolError>`**
   - Runs all test vectors against the tool.
   - For each test vector: invoke tool with test input, compare output to expected output.
   - Returns a result with per-vector pass/fail status and overall integrity assessment.
   - Appends `ToolVerified` event to event log.

6. **Cross-context tool interfaces:**

```rust
pub struct ToolInterface {
    pub source_context: ContextId,      // Context exposing the tool
    pub target_context: ContextId,      // Context consuming the tool
    pub tool_id: ToolId,                // Which tool is exposed
    pub rate_limit: Option<RateLimit>,  // Calls per time window
    pub approved_by_source: bool,       // Source context opted in
    pub approved_by_target: bool,       // Target context opted in
}
```

   - **`expose_tool(context: &ContextHandle, tool_id: &ToolId, to_context: &ContextId) -> Result<ToolInterface, ToolError>`**: Initiates a tool interface proposal from the source context. Requires admin capability.
   - **`accept_tool_interface(context: &ContextHandle, interface: &ToolInterface) -> Result<(), ToolError>`**: Target context accepts the interface. Requires admin capability. Both `approved_by_source` and `approved_by_target` must be true before calls are permitted.
   - **`invoke_cross_context(source_context: &ContextHandle, interface: &ToolInterface, input: serde_json::Value, invoker_did: &DID) -> Result<serde_json::Value, ToolError>`**: Invokes a tool across context boundaries. Source context governance checks outbound. Target context governance checks inbound. Both event logs record the call with provenance.
   - Rate limiting enforced per interface.

7. **Stateful tool sessions (spec section 6.2.1):**

```rust
pub struct ToolSession {
    pub session_id: String,
    pub tool_id: ToolId,
    pub source_context: ContextId,
    pub state: serde_json::Value,       // Opaque session state
    pub created_at: u64,
    pub ttl: Duration,
    pub call_count: u64,
}
```

   - **`create_session(context: &ContextHandle, tool_id: &ToolId, source_context: &ContextId, ttl: Duration) -> Result<String, ToolError>`**: Creates a new session. Returns session ID.
   - **`invoke_session(context: &ContextHandle, session_id: &str, input: serde_json::Value) -> Result<serde_json::Value, ToolError>`**: Invokes a tool within an active session. Each call is individually governed. Session state is updated by the tool.
   - **Session cleanup:** Background task removes sessions past their TTL. Session state is internal to the tool's context.

### Scope

**Files (~4-6):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `ToolId` type, re-exports |
| `registry.rs` | `ToolRegistration`, tool storage per context, `register_tool`, `update_tool`, `verify_tool` |
| `invoke.rs` | `invoke_tool`, input/output schema validation, tool dispatch |
| `interface.rs` | `ToolInterface`, `expose_tool`, `accept_tool_interface`, `invoke_cross_context`, rate limiting |
| `session.rs` | `ToolSession`, `create_session`, `invoke_session`, TTL cleanup task |
| `schema.rs` | JSON Schema validation helpers, MCP compatibility utilities |
| `lifecycle.rs` | `ToolRequest`, `ToolResponse`, `ToolCancel`, `ToolStatus`, timeout management, cancellation handling |

**Estimated functions:** ~18-22 public functions, ~12-15 internal helpers.

---

## ADR-011: Verifiable Event Log (Merkle Tree)

**Status:** Decided

### Context

Every context maintains a verifiable event log — an append-only Merkle tree of all protocol events (spec section 7.3.1). The event log transforms claims about context history from trust-dependent to validation-dependent. Any participant can verify claims against the Merkle root: proof-of-inclusion ("this event happened"), proof-of-absence ("this event did not happen"), and consistency ("our views of history match").

The event log is the foundation for participation validation (spec Layer 2), participation records (spec section 7.3.2), the Relay Consistency Protocol (spec section 9.9.3), and equivocation detection. Without a verifiable event log, accountability claims are unverifiable assertions.

### Decision

Implement an append-only Merkle tree per context in `scp-core/event_log/`. The tree uses SHA-256 hashing following the Certificate Transparency (RFC 6962) structure: leaf nodes are SHA-256 hashes of events, and interior nodes are SHA-256 hashes of their children's concatenated hashes. The log supports four core operations: append, prove inclusion, prove absence, and verify. Consistency checkpoints (spec section 9.9.3) are computed at regular intervals and exchanged between members to detect relay equivocation.

### Rationale

- **Certificate Transparency structure:** CT's Merkle tree design is well-studied, formally verified, and optimized for append-only logs with efficient inclusion and consistency proofs. The proof sizes are O(log n) for a tree with n leaves. This is not a novel data structure — it is a proven one applied to a new domain.
- **SHA-256 over other hash functions:** Consistent with the rest of SCP's crypto stack (MLS ciphersuite uses SHA-256, envelope hashes use SHA-256). Single hash function simplifies the security analysis.
- **Append-only (no delete, no modify):** Events are permanent. Even in ephemeral contexts, the event log structure persists (only the encryption keys are destroyed, making the event content unreadable, but the Merkle structure and hashes remain for accountability).
- **Per-context, not global:** Each context has its own independent Merkle tree. There is no global event log. This is consistent with SCP's context-as-isolation-boundary design.
- **Consistency checkpoints:** Per spec section 9.9.3, members periodically exchange signed Merkle roots. If two members have different roots for the same event count, the relay is equivocating (showing different histories to different members). Detection requires only two honest members.

### Implementation

- **Language:** Rust
- **Hashing:** SHA-256 via `sha2` crate
- **Storage:** In-memory for Phase 2 initial development, backed by `ProtocolRepository` (§17.4) for persistence. Event log keys follow the convention in §17.3: `context/{context_id}/event/{seq:020d}` for events, `context/{context_id}/event_tree/{level}/{index}` for Merkle tree nodes.
- **Crate:** `scp-core`
- **Module:** `scp-core/event_log/`
- **Proof format:** Binary serialization of inclusion proof paths (sibling hashes + left/right indicators).

### Dependencies

- **ADR-008 (Context):** The event log is owned by a context. Every context state transition is an event. The Context Manager appends events to the log.
- **ADR-002 (Envelope):** Events reference envelope hashes for message events.
- **ADR-003 (DID):** Events are signed by the acting agent's DID. The `Event` struct includes a `signing_key_id` field (ADR-039) identifying which verification method signed (e.g., `"#active"` or `"#agent"`), enabling verifiers to resolve the correct public key from the actor's DID document. Checkpoint signatures are verified against DID public keys.

### Acceptance Criteria

1. **`EventLog` struct and event types:**

```rust
pub struct EventLog {
    leaves: Vec<[u8; 32]>,          // SHA-256 hashes of events
    tree: Vec<Vec<[u8; 32]>>,       // Interior node layers
    context_id: ContextId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_type: EventType,
    pub actor_did: DID,
    pub signing_key_id: String,     // Which VM signed: "#active" or "#agent" (ADR-039)
    pub timestamp: u64,
    pub sequence: u64,              // Monotonic event sequence within this log
    pub payload: EventPayload,      // Type-specific data
    pub prev_hash: [u8; 32],        // Hash of the previous event (hash chain)
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    ContextCreated,
    ContextClosing,
    ContextClosed,
    ContextExpired,
    MemberJoined,
    MemberLeft,
    RoleAssigned,
    TokenRevoked,
    MessageSent,
    ToolRegistered,
    ToolUpdated,
    ToolInvoked,
    ToolVerified,
    ToolInterfaceEstablished,
    GovernanceAction,
    ConsistencyCheckpoint,
    AbsenceProofRequested,
    MemberBlocked,          // ADR-007: Signed block notification recorded for auditability
    KeyEpochAdvance,        // ADR-007: Sender key epoch rotation (shared across Encrypted and Broadcast modes)
}
```

2. **`append(log: &mut EventLog, event: Event) -> Result<u64, EventLogError>`**
   - Computes `leaf_hash = SHA256(serialize(event))`.
   - Verifies `event.prev_hash` matches the hash of the last leaf (hash chain integrity).
   - Verifies event signature against `event.actor_did`.
   - Appends leaf hash to the tree.
   - Recomputes affected interior nodes.
   - Returns the leaf index (position in the log).

3. **`prove_inclusion(log: &EventLog, leaf_index: u64) -> Result<InclusionProof, EventLogError>`**
   - Returns the Merkle path from the leaf to the root.
   - Proof consists of sibling hashes at each tree level and left/right direction indicators.
   - Proof size: O(log n) hashes where n is the number of leaves.

```rust
pub struct InclusionProof {
    pub leaf_index: u64,
    pub leaf_hash: [u8; 32],
    pub path: Vec<ProofStep>,
    pub root: [u8; 32],
}

pub struct ProofStep {
    pub sibling_hash: [u8; 32],
    pub direction: Direction,       // Is sibling Left or Right of our path
}
```

4. **`prove_absence(log: &EventLog, event_hash: &[u8; 32]) -> Result<AbsenceProof, EventLogError>`**

   Non-membership proofs use a **sorted leaf hash** approach with a documented privacy trade-off.

   ```rust
   pub struct AbsenceProof {
       /// The event hash being proven absent.
       pub query_hash: [u8; 32],
       /// The two adjacent leaf hashes that bracket the query hash
       /// in sorted order. If query_hash < all leaves, `lower` is None.
       /// If query_hash > all leaves, `upper` is None.
       pub lower: Option<LeafWithProof>,
       pub upper: Option<LeafWithProof>,
       /// Merkle root at the time of the proof.
       pub root: [u8; 32],
       /// Total number of leaves in the log.
       pub leaf_count: u64,
   }

   pub struct LeafWithProof {
       pub leaf_hash: [u8; 32],
       pub leaf_index: u64,
       pub inclusion_proof: InclusionProof,
   }
   ```

   **Algorithm:**
   1. Maintain a sorted index of leaf hashes alongside the append-order Merkle tree (`BTreeSet<([u8; 32], u64)>`).
   2. To prove absence of `query_hash`: find the two adjacent entries that bracket `query_hash`. Generate inclusion proofs for both.
   3. The verifier confirms: (a) both adjacent leaves are in the tree, (b) they are truly adjacent in sorted order, (c) `query_hash` falls between them.

   **Privacy analysis:** This approach reveals exactly two leaf hashes (the neighbors of the query point). It does NOT require disclosing the full leaf hash set.

   **Residual privacy risk:** Repeated absence queries can gradually reveal more of the sorted hash set. Mitigation: absence proof requests are rate-limited (maximum 10 per member per hour per context) and logged as `AbsenceProofRequested` events. Context governance can restrict which roles may request absence proofs (default: `admin` only).

5. **`verify_inclusion(proof: &InclusionProof) -> bool`**
   - Recomputes the root hash from the leaf hash and proof path.
   - Returns true if the computed root matches the proof's stated root.
   - Pure function — no access to the log needed. Any third party can verify.

6. **`root(log: &EventLog) -> [u8; 32]`**
   - Returns the current Merkle root hash of the log.
   - O(1) — the root is always maintained as the log is appended to.

7. **`event_count(log: &EventLog) -> u64`**
   - Returns the number of events in the log.

8. **Consistency checkpoints (spec section 9.9.3):**

```rust
pub struct ConsistencyCheckpoint {
    pub context_id: ContextId,
    pub sender_did: DID,
    pub event_count: u64,
    pub merkle_root: [u8; 32],
    pub epoch: Option<u64>,         // Current MLS epoch (None for Broadcast contexts)
    pub timestamp: u64,
    pub signature: Ed25519Signature,
}
```

   - **`generate_checkpoint(log: &EventLog, sender_did: &DID, epoch: u64, signing_key: &KeyHandle, signing_key_id: &str) -> Result<ConsistencyCheckpoint, EventLogError>`**: Creates and signs a checkpoint from the current log state. The `signing_key_id` (ADR-039) identifies which verification method signed (accepts `"#active"` or `"#agent"`).
   - **`compare_checkpoint(local_log: &EventLog, remote_checkpoint: &ConsistencyCheckpoint) -> CheckpointComparison`**: Compares a received checkpoint against local state. Returns `Consistent`, `Divergent { first_divergent_event: Option<u64> }`, `Behind { missing_events: u64 }`, or `Ahead { extra_events: u64 }`.
   - Checkpoints are generated every 50 events or every 10 minutes, whichever comes first (spec section 9.9.3).
   - Checkpoints are sent as regular MLS application messages.
   - Divergent Merkle roots for the same event count indicate equivocation — trigger alert and divergence resolution.

### Scope

**Files (~3-4):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `EventLog` struct, `Event`, `EventType`, re-exports |
| `tree.rs` | Merkle tree operations: `append`, `root`, `event_count`, internal node computation, tree maintenance |
| `proof.rs` | `prove_inclusion`, `prove_absence`, `verify_inclusion`, `InclusionProof`, `AbsenceProof` types |
| `checkpoint.rs` | `ConsistencyCheckpoint`, `generate_checkpoint`, `compare_checkpoint`, checkpoint scheduling logic |

**Estimated functions:** ~12-15 public functions, ~8-10 internal helpers.

---

## ADR-012: Multi-Transport Routing

**Status:** Decided

### Context

SCP is transport-independent (architecture.md section 7). No single transport is primary. The `TransportAdapter` trait (ADR-005) defines the contract each adapter implements, and the `TransportManager` (ADR-005 acceptance criterion 3) was stubbed in Phase 1 to support a single adapter. Phase 2 completes the `TransportManager` with multi-transport routing: sending envelopes to multiple relays for suppression resistance, partitioning relay sets across contexts for metadata privacy, mixing real and decoy subscriptions, and scoring relay reliability.

Decision 10 mandates relay set partitioning and multi-relay publishing. Decision 6 mandates persistent connections and TLS for all relay connections. These metadata privacy measures are enforced at the transport routing layer, transparent to the context and envelope layers above.

### Decision

Implement the full `TransportManager` in `scp-transport/manager.rs` with multi-adapter routing, per-context relay set assignment, suppression-resistant multi-relay publishing (3+ relays per context), and per-relay reliability scoring. The TransportManager is the single entry point for all transport operations — the context layer never interacts with individual adapters directly.

### Rationale

- **Multi-relay publishing for suppression resistance (spec section 9.9.2):** Publishing to a single relay gives that relay veto power over message delivery. Publishing to 3+ relays means all 3 must collude to suppress a message. The TransportManager handles multi-relay fanout transparently.
- **Relay set partitioning (Decision 10):** Each context SHOULD use different relays. If Context A and Context B share the same relay, that relay can correlate the client's activity across both contexts (even with per-context pseudonyms, the connection source is the same). Partitioning distributes contexts across the available relay pool to minimize overlap.
- **Per-relay reliability scoring:** Relays are untrusted (spec section 9.9.1). A relay that drops messages, delays delivery, or retains data after deletion requests should be deprioritized. The TransportManager tracks delivery success rates, latency, and deletion compliance per relay and routes accordingly.
- **Single entry point:** The context layer calls `transport_manager.send(envelope)` and `transport_manager.subscribe(routing_id)`. It does not know or care how many relays are involved or which adapters are used. This separation keeps the context layer clean and the transport layer independently evolvable.

### Implementation

- **Language:** Rust
- **Async runtime:** tokio (multi-relay fanout, stream merging, timer-based scoring)
- **Stream merging:** `tokio-stream` or `futures` for merging subscription streams from multiple adapters with deduplication.
- **Crate:** `scp-transport`
- **Module:** `scp-transport/manager.rs` (completing the stub from ADR-005)
- **Relay discovery:** Relay lists are published in DID documents (spec section 9.10.2). The TransportManager reads relay lists from resolved DID documents for recipients.

### Dependencies

- **ADR-005 (Transport Trait):** The TransportManager operates on `Box<dyn TransportAdapter>` instances. All routing logic works through the trait interface.
- **ADR-004 (Native Relay):** The SCP native relay adapter is always available. It implements `TransportAdapter`.
- **ADR-002 (Envelope):** The TransportManager routes `OuterEnvelope` objects. It uses `routing_id` for subscription matching and `blob_id` for deduplication.
- **ADR-008 (Context):** The TransportManager receives relay set assignments per context from the Context Manager.

### Acceptance Criteria

1. **`TransportManager` completion (from ADR-005 stub):**

```rust
pub struct TransportManager {
    adapters: Vec<Box<dyn TransportAdapter>>,
    relay_assignments: HashMap<ContextId, Vec<usize>>,  // Context -> adapter indices
    reliability_scores: HashMap<String, ReliabilityScore>,
    dedup_cache: LruCache<BlobId, ()>,                   // Seen blob IDs
}
```

2. **`send(manager: &TransportManager, envelope: &OuterEnvelope, context_id: &ContextId) -> Result<Vec<BlobId>, TransportError>`**
   - Looks up the relay set for this context.
   - Sends the envelope to ALL relays in the context's relay set (minimum 3, spec section 9.9.2).
   - Fanout is concurrent (tokio::join or FuturesUnordered).
   - Returns a `BlobId` per successful relay.
   - If fewer than 2 relays succeed, returns an error (insufficient redundancy).
   - Records delivery success/failure per relay for reliability scoring.

3. **`subscribe(manager: &TransportManager, routing_id: &RoutingId, context_id: &ContextId, since: Option<u64>) -> Result<Pin<Box<dyn Stream<Item = TransportEvent> + Send>>, TransportError>`**
   - Subscribes to the routing_id on all relays in the context's relay set.
   - For broadcast contexts, `routing_id` is the public `SHA-256(context_id)` — any subscriber that knows the context_id can derive the routing_id and subscribe without prior membership negotiation.
   - Merges streams from all relays into a single deduplicated stream.
   - Deduplication applies to `TransportEvent::Envelope` variants: envelopes with the same `blob_id` (SHA-256 of the blob) are delivered only once. The dedup cache uses LRU eviction with a 10,000-entry capacity **and** time-based expiry (1 hour default, configurable via `TransportConfig`). Entries older than the TTL are evicted even if the capacity has not been reached. This prevents stale entries from consuming memory in low-throughput scenarios and ensures that a slow relay delivering a blob after the LRU entry was evicted does not bypass deduplication.
   - Returns the merged, deduplicated stream.

4. **`assign_relay_set(manager: &mut TransportManager, context_id: &ContextId) -> Vec<usize>`**
   - Assigns a relay set for a new context.
   - Minimizes overlap with existing context relay sets (Decision 10: relay set partitioning).
   - Algorithm: round-robin with spread — distribute contexts across adapters to minimize the maximum overlap between any two contexts' relay sets.
   - Selects at least 3 relays per context.
   - Prefers relays with higher reliability scores.

5. **`ReliabilityScore` and scoring:**

```rust
pub struct ReliabilityScore {
    pub relay_url: String,
    pub delivery_success_rate: f64,     // 0.0 to 1.0
    pub average_latency_ms: u64,
    pub deletion_compliance_rate: f64,  // 0.0 to 1.0
    pub last_updated: u64,
    pub total_sends: u64,
    pub total_failures: u64,
}
```

   - **`update_score(manager: &mut TransportManager, relay_url: &str, outcome: DeliveryOutcome)`**: Updates the relay's score after each operation.
   - **`get_score(manager: &TransportManager, relay_url: &str) -> Option<&ReliabilityScore>`**: Returns current score for a relay.
   - Scores decay over time (exponential moving average) so recent behavior weighs more than historical.
   - Relays with delivery success rate below 0.5 are flagged for replacement.
   - Relays with deletion compliance rate below 0.5 are deprioritized for ephemeral contexts (spec section 5.11).

7. **Multi-relay cross-check (spec section 9.9.2):**
   - When the merged subscription stream receives an envelope from one relay but not from another within 30 seconds, the lagging relay is marked as potentially adversarial.
   - Track per-blob delivery across relays: `HashMap<BlobId, HashSet<usize>>` (blob -> set of adapters that delivered it).
   - After the 30-second window, blobs delivered by fewer than half the context's relays trigger a suppression warning.

### Scope

**Files (~2-3):**

| File | Purpose |
|------|---------|
| `manager.rs` | `TransportManager` — send with multi-relay fanout, subscribe with stream merging and dedup, relay set assignment, reliability scoring, cross-check |
| `scoring.rs` | `ReliabilityScore`, score update logic, exponential moving average, relay ranking |

**Estimated functions:** ~15-18 public functions, ~10-12 internal helpers.

**Testing.** The `scp-testing` crate (§16) provides `InMemoryTransport` — a `TransportAdapter` implementation backed by `InMemoryRelay` instances — enabling deterministic testing of `TransportManager` routing logic without network I/O. The `transport_conformance!()` macro (§16.12.1) verifies that every `TransportAdapter` implementation satisfies the trait contract; the `InMemoryTransport` is the reference, and the native relay adapter must pass the same suite. Multi-relay fault scenarios (suppression, equivocation, delay, replay) are tested via `BehaviorMode` configurations on `InMemoryRelay` (§16.4.4).

---

## Phase 2 Integration Test

The ultimate acceptance criterion for Phase 2 exercises all 5 ADRs together with the Phase 1 crypto stack:

```
1. Alice creates an identity (ADR-003) and a context with ceiling [messaging, tool_invoke],
   roles [admin, member], one tool "calculator", TTL 5 minutes, memory scope ephemeral (ADR-008)
2. The context is assigned to 3 relays via TransportManager (ADR-012)
3. Bob creates an identity, discovers the context, and joins (ADR-008)
4. Bob is assigned the "member" role with UCAN tokens for messages:read, messages:write,
   tool_invoke_all (ADR-009)
5. Alice sends a message. UCAN is validated. Envelope is created, multi-relay published (ADR-012).
   Event is logged in the Merkle tree (ADR-011).
6. Bob receives the message via merged subscription stream (ADR-012).
   Bob's SDK deduplicates across relays.
7. Bob invokes the "calculator" tool with input {"operation": "add", "a": 1, "b": 2} (ADR-010).
   UCAN validates Bob has tool_invoke capability.
   Tool returns {"result": 3}. Invocation is logged (ADR-011).
8. Bob attempts to assign a role (he's a member, not admin). UCAN validation rejects —
   Bob lacks RoleAssign capability (ADR-009). Action is denied.
9. Both Alice and Bob generate consistency checkpoints (ADR-011). Merkle roots match.
10. TTL expires. Context transitions to Expired (ADR-008). MLS group and sender keys are destroyed.
    Relay deletion requests are sent for all context blobs.
11. The event log's Merkle tree remains — the structure (hashes, proofs) survives even though
    the encrypted content is now unreadable.
12. Throughout: relay reliability
    is tracked, and relay sets are partitioned across contexts.
```

This test proves: context lifecycle works, roles enforce, tools invoke, event logs verify, multi-transport routes, TTL enforces, metadata privacy measures are active, and everything composes cleanly on top of Phase 1's crypto stack.

---

## ADR-032: Addressability and Deployment

> **Note:** ADR-032 is numbered non-sequentially because it was added as a cross-cutting concern after the original phase numbering was established. It lives in the Phase 2 document because its scope (relay discovery, `.well-known/scp`, URI format) is transport-adjacent and depends on Phase 1–2 ADRs. See also ADR-033 in phase-3.md.

**Status:** Decided

### Context

SCP's protocol layer (identity, contexts, relays, encryption) is fully specified. What's missing is how things get found and how complete applications get deployed. Today:
- No standard DID service endpoint type for "this is my SCP relay"
- No HTTP-level discovery from a domain name (no `.well-known/scp`)
- No universal context URI scheme (only `scp://broadcast/...` exists)
- No SDK bootstrap story (how a client learns its first relay — open question in §00)
- No deployment pattern for "relay + participant + HTTP server on one box"

SCP-033 (TransportManager multi-relay) consumes relay lists from DID documents but nothing writes them there. The relay discovery open question in §00 explicitly states this gap.

### Decision

Implement a complete addressability and deployment layer as specified in §18:

1. **`SCPRelay` DID service endpoint type** (§18.2.1) — transport-layer relay URLs in DID documents, distinct from `SCPCapabilities` (ADR-020, application-layer). Self-certified via BEP44.
2. **`.well-known/scp`** (§18.3) — advisory HTTP on-ramp for web discovery. NOT self-certifying. Clients MUST verify against DHT-resolved DID documents. Exposes relay URLs, operator DID, relay config, and broadcast context IDs only.
3. **Universal context URI** (§18.4) — `scp://context/<hex>?relay=<url>[&mode=...][&name=...]`. Discovery-only, no embedded key material. Legacy `scp://broadcast/...` accepted as alias.
4. **Relay bootstrap priority chain** (§18.5) — explicit config → DID document → `.well-known/scp` → peer discovery → fallback list. Closes §00 open question.
5. **`ApplicationNode`** (§18.6) — concrete SDK type in new `scp-node` crate. Composes relay server + identity + HTTP server + TLS (ACME). Not an HTTP framework — exposes axum Router instances for composition.

### Rationale

- **SCPRelay vs SCPCapabilities:** Different consumers, different purposes. TransportManager needs relay URLs (transport). Discovery Engine needs capability schemas (application). Conflating them forces both consumers to parse the same entry and filter. Separate types are cleaner.
- **`.well-known/scp` is advisory, not trusted:** HTTPS-dependent discovery cannot provide the self-certifying guarantees of DID+DHT. Making the trust boundary explicit prevents false confidence. The verification chain (§18.3.2) gives BEP44-grade assurance when performed.
- **Context URIs are discovery-only:** Embedding key material in URIs creates a shareable key — anyone with the URI could derive access. MLS membership is a separate, governed flow. URIs point to metadata for inspection, not access.
- **`ApplicationNode` is composition, not framework:** Prescribing an HTTP framework locks out existing ecosystems. Exposing axum Routers lets applications compose SCP infrastructure into their existing server architecture.
- **ACME HTTP-01 needs port 80:** This is the simplest path for most deployments. DNS-01 alternative covers environments without port 80 access (NAT, shared hosting).

### Dependencies

- **ADR-003 (DID):** SCPRelay extends the DID document with a new service entry type. Relay URL publication extends the DID publish flow.
- **ADR-004 (Native Relay):** The relay server in ApplicationNode implements ADR-004. The `wss://<host>/scp/v1` URL format comes from ADR-004. Relay operator config fields in `.well-known/scp` mirror ADR-004's configuration table.
- **ADR-012 (TransportManager):** TransportConfig and relay bootstrap resolution wire into TransportManager initialization. Multi-relay fanout (ADR-012) is the federation mechanism (§18.7).
- **ADR-020 (SCPCapabilities):** SCPRelay is distinguished from SCPCapabilities as separate DID service types (§18.2.2).

### Acceptance Criteria

1. **`SCPRelay` service entry type** exists in `DidDocument`. `add_relay_service(url)` adds an entry. `relay_service_urls()` returns all relay URLs. Serde roundtrip preserves SCPRelay entries alongside existing service types (PreRotationCommitment, IdentityPrivateState).

2. **DID publish flow** accepts optional `relay_urls: Vec<Url>`. When provided, relay URLs appear as SCPRelay service entries in the published DID document. BEP44 signature covers relay entries. Sequence number monotonicity (§9.6.3) applies to relay list updates.

3. **`ScpUri` type** parses and serializes the universal context URI format: `scp://context/<hex>?relay=<url>[&relay=<url2>][&mode=...][&name=...]`. Legacy `scp://broadcast/<hex>?relay=<url>` accepted as alias. Invalid URIs return typed errors. Percent-encoding per RFC 3986. Parse/serialize roundtrip.

4. **`WellKnownScp` type** serializes/deserializes the `.well-known/scp` JSON format. Fields: version, did, relay, optional contexts, optional relay_config. Validation rejects encrypted context IDs in contexts list. All optional fields behave correctly when absent.

5. **`TransportConfig` struct** with relay_urls (explicit), bootstrap_domain (optional), dedup_cache_size, dedup_cache_ttl. `ResolveRelays` trait implements the bootstrap priority chain (§18.5.1). TransportManager accepts TransportConfig at initialization.

6. **`scp-node` crate** with `ApplicationNode` builder: `.domain()`, `.identity()` / `.generate_identity()`, `.storage()`, `.build()`. Build wires relay server start, DID publication with SCPRelay entries, storage initialization. `node.relay()`, `node.identity()`, `node.storage()` accessors work.

7. **TLS provisioning:** ACME HTTP-01 challenge handler. Certificate storage in SqliteStorage. Auto-renewal 30 days before expiry. TLS 1.3 enforced.

8. **HTTP server:** `node.well_known_router()` returns axum Router serving `GET /.well-known/scp` with dynamically generated content. `node.relay_router()` returns axum Router handling WebSocket upgrade at `/scp/v1`. `node.serve(app_router)` merges routes and binds HTTPS.

9. **Integration test:** ApplicationNode starts → DID published → `.well-known/scp` reachable → relay accepts connections. Client discovers relay via `.well-known/scp` → verifies against DID → connects → subscribes. `scp://` URI roundtrip through creation and parsing.

### Scope

**New crate:**

| Crate | Files | Purpose |
|-------|-------|---------|
| `scp-node` | `lib.rs`, `http.rs`, `tls.rs`, `well_known.rs` | ApplicationNode builder, HTTP routing, TLS provisioning |

**Modified files:**

| File | Change |
|------|--------|
| `scp-core/src/identity/document.rs` | Add SCPRelay service entry type |
| `scp-core/src/identity/dht.rs` | Wire relay URL publication into DID publish |
| `scp-core/src/uri.rs` (new) | ScpUri type, parsing, serialization |
| `scp-core/src/well_known.rs` (new) | WellKnownScp type, serialization |
| `scp-transport/src/config.rs` (new) | TransportConfig, ResolveRelays trait |
| `scp-transport/src/manager.rs` | Accept TransportConfig at init |
| `Cargo.toml` | Add scp-node workspace member |

**Estimated functions:** ~30-35 public functions, ~20-25 internal helpers across all files.

---

## ADR-035: Local HTTP Control API and Broadcast Projection

> **Note:** ADR-035 is numbered non-sequentially (same pattern as ADR-032). Both features are `ApplicationNode`-scope extensions that depend on Phase 2 ADRs and live in the `scp-node` crate. They are application-layer conveniences, not protocol changes.

**Status:** Decided

### Context

SCP's core transport is MessagePack-over-WebSocket with encrypted blobs — deliberately opaque to intermediaries (§9.9.1). This is architecturally correct (relays are dumb pipes), but it means:

1. **No dev tooling interop.** Standard HTTP tools (curl, Postman, OpenAPI) cannot inspect node state or relay status. Operators debugging a deployment must write Rust code or use the SDK CLI.
2. **No HTTP distribution for broadcast content.** Broadcast contexts (§5.14) produce content intended for broad audiences, but that content is only accessible to SCP clients with broadcast keys. CDNs, web browsers, RSS readers, and search crawlers are excluded.

Both gaps are recoverable at the application layer without compromising the wire protocol.

### Decision

Implement two `ApplicationNode` features in the `scp-node` crate:

#### 1. Local HTTP Control API (§18.10)

- **Separate port.** Dev API listens on `127.0.0.1:<port>`, distinct from the public HTTPS listener. Prevents accidental exposure through reverse proxy misconfiguration.
- **Bearer token authentication.** Token format: `scp_local_token_<32 random hex>`. Generated at startup, logged at INFO. All `/scp/dev/v1/*` requests require `Authorization: Bearer <token>`. 401 on missing/wrong token.
- **Seven endpoints.** Health, identity, relay status, context list/get/create/delete. All JSON. Read-only for node state; context management via POST/DELETE.
- **Opt-in.** Enabled via `.local_api(addr)` on the builder. Production default: disabled (zero additional attack surface).

#### 2. HTTP Broadcast Projection (§18.11)

- **Public HTTPS port.** Projection endpoints serve on the same listener as `.well-known/scp` and `/scp/v1`.
- **Context-governed auth.** Open contexts serve publicly; gated contexts require `messagesRead` UCAN. Per-author `ProjectionPolicy` overrides within admission bounds (§18.11.2.1).
- **Author-side only.** The relay cannot decrypt (§9.9.1). The author's `ApplicationNode` holds the broadcast keys and decrypts its own content for HTTP serving. Subscriber-side projection is deliberately unsupported.
- **Feed endpoint.** `GET /scp/broadcast/<routing_id>/feed` — paginated JSON with 30s cache TTL and ETag.
- **Per-message endpoint.** `GET /scp/broadcast/<routing_id>/messages/<blob_id>` — immutable individual messages with 1-year cache TTL and conditional GET (304).
- **Opt-in per context.** `enable_broadcast_projection(context_id, broadcast_key, admission, projection_policy)` activates projection. `disable_broadcast_projection(context_id)` deactivates.

#### 3. Shared BlobStorage via Arc

`RelayServer::new` currently takes an owned `B: BlobStorage`, wrapping it in `Arc<B>` internally. Broadcast projection needs to query the same `BlobStorage` instance that the relay writes to. The change: the `ApplicationNode` builder creates `Arc<B>`, passing `Arc::clone` to both `RelayServer` and `NodeState`. This requires `RelayServer::new` to accept `Arc<B>` instead of owned `B`.

### Rationale

- **Separate port for dev API:** A reverse proxy forwarding `*` to the public HTTPS port is a common deployment pattern. If the dev API shared the public port, every such proxy would expose it. Separate port requires explicit, intentional proxy configuration. The trade-off (two listeners) is negligible.
- **Projection auth follows context admission mode:** §5.14 defines broadcast contexts with two admission models — open (keys distributed on DID registration) and gated (keys require `messagesRead` UCAN). Projection endpoints enforce the same access model: open contexts serve publicly; gated contexts require a valid `messagesRead` UCAN in the `Authorization: Bearer` header. Per-author `ProjectionPolicy` overrides (§18.11.2.1) provide granularity within the bounds set by the admission mode — a gated context cannot have public per-author overrides (the admission mode is the floor). Gated projection responses use `Cache-Control: private` to prevent CDN caching of authenticated content.
- **Author-side only:** Subscriber-side projection would let any subscriber redistribute content via HTTP without the author's control or knowledge. Author-side projection means the author explicitly opts in.
- **`routing_id` in URLs is not new disclosure:** `routing_id = SHA-256(context_id)` is already visible to every relay handling the broadcast context (§5.14.6). Using it in HTTP URLs reveals nothing beyond what relays already observe.
- **`Arc<dyn BlobStorage>` sharing over IPC:** A separate `scp-broadcast-proxy` process would require IPC (Unix socket, shared memory) to access blobs. The keys and blobs are already in-process in the `ApplicationNode`. `Arc` sharing is zero-copy, zero-overhead.

### Rejected Alternatives

1. **Relay-side projection.** Relays cannot decrypt broadcast content (§9.9.1). Giving relays broadcast keys would violate the untrusted-relay invariant and expand the trust boundary.
2. **Separate `scp-broadcast-proxy` process.** Adds IPC complexity for zero benefit — keys and blobs are already in the `ApplicationNode` process. If operators want a separate process, they can run a second `ApplicationNode` with projection enabled.
3. **UNIX socket for dev API.** Not portable across deployment modes (containers, Windows). TCP on localhost is universally supported.
4. **Dev API on the public port with path-based routing.** Accidental exposure risk through reverse proxy misconfiguration outweighs the convenience of a single port.

### Dependencies

- **ADR-032 (Addressability and Deployment):** `ApplicationNode` builder, `NodeState`, `serve()`, axum Router composition.
- **ADR-007 (BroadcastKey):** `BroadcastKey` type, `BroadcastEnvelope` seal/open operations. Key epoch management.
- **ADR-004 (Native Relay):** `RelayServer`, `BlobStorage` trait, `query(routing_id, since, limit)` interface. `Arc<B>` change to `RelayServer::new`.

### Acceptance Criteria

1. **Dev API bearer token** generated at startup, logged at INFO, available via `node.dev_token()`.
2. **Dev API bound to localhost** on a separate port from the public HTTPS listener.
3. **`GET /scp/dev/v1/health`** returns uptime, relay connection count, and storage status.
4. **`GET /scp/dev/v1/identity`** returns DID string and DID document.
5. **`GET /scp/dev/v1/relay/status`** returns bound address, active connections, and blob count.
6. **`GET /scp/dev/v1/contexts`** returns list of registered broadcast contexts.
7. **`GET /scp/dev/v1/contexts/:id`** returns single context details. 404 for unknown ID.
8. **`POST /scp/dev/v1/contexts`** registers a broadcast context. 201 on success.
9. **`DELETE /scp/dev/v1/contexts/:id`** deregisters a context. 204 on success. 404 for unknown ID.
10. **Bearer token middleware** returns 401 for missing or invalid token on all dev API endpoints.
11. **`enable_broadcast_projection`** activates HTTP projection for a broadcast context.
12. **Feed endpoint** returns paginated JSON with `Cache-Control: public, max-age=30, stale-while-revalidate=300` and `ETag`.
13. **Per-message endpoint** returns single message JSON with `Cache-Control: public, immutable, max-age=31536000` and `ETag`.
14. **Conditional GET** on per-message endpoint: `If-None-Match` with matching ETag returns 304.
15. **`ProjectedContext` registry** maps `routing_id → BroadcastKey` per epoch. Decryption uses epoch-matched key.
16. **`RelayServer::new` accepts `Arc<B>`** so the same `BlobStorage` instance is shared between relay and projection handlers.

### Scope

**New files:**

| File | Purpose |
|------|---------|
| `crates/scp-node/src/dev_api.rs` | Dev API handlers + bearer auth middleware |
| `crates/scp-node/src/projection.rs` | `ProjectedContext` type + broadcast projection handlers |

**Modified files:**

| File | Change |
|------|--------|
| `crates/scp-node/src/lib.rs` | `NodeState` extensions (dev token, dev bind addr, projected contexts, `Arc<dyn BlobStorage>`), new builder methods, new `ApplicationNode` methods |
| `crates/scp-node/src/http.rs` | Wire `dev_router()` and `broadcast_projection_router()` into `serve()`, add dev API listener |
| `crates/scp-transport/src/native/server.rs` | `RelayServer::new` accepts `Arc<B>` instead of owned `B` |

**Estimated functions:** ~15-20 public functions, ~10-15 internal helpers across new and modified files.

---

## ADR-036: Transport Profiles and Adaptive Resource Management

**Status:** Decided

### Context

SCP's native relay transport (ADR-004) uses persistent WebSocket connections with 30-second PING keepalive and 30-second cover traffic intervals per connection. Each context is assigned a minimum of 3 relays for suppression resistance (§9.10.1), meaning a single participant maintains at minimum 3 persistent TCP connections per context. This model works well for desktop and server deployments but creates real resource problems for:

1. **Mobile devices:** Each persistent WebSocket holds an open TCP connection, preventing the radio from entering low-power idle. The 30-second cover traffic and 30-second PING intervals wake the radio 4 times per minute per connection. With 3 relays per context and multiple active contexts, battery drain is significant.
2. **IoT and embedded devices:** Many constrained devices cannot sustain TCP connections at all — they use UDP-based protocols (CoAP, DTLS datagrams), have kilobytes of RAM, and operate on low-power duty cycles. WebSocket is architecturally incompatible.
3. **High-connection-count relays:** Each WebSocket connection consumes server memory for TCP state, TLS session, and subscription registry entries. A relay serving thousands of participants must manage thousands of persistent connections with their associated cover traffic overhead.

The existing cover traffic configuration (§9.10.6) was binary: enabled or disabled. This is too coarse — mobile devices need cover traffic but at reduced frequency, while constrained devices genuinely cannot afford any.

### Decision

Introduce named transport profiles and tiered cover traffic configuration to adapt SCP's transport behavior to device capabilities.

**Transport profiles** (§10.13): Four named profiles — `server`, `desktop`, `mobile`, `constrained` — each bundling connection strategy, cover traffic tier, minimum relay count, reconnect behavior, and maximum connection budget. The SDK infers a profile from the platform at initialization, overridable by the application.

**Cover traffic tiers** (§9.10.6 amended): Replace `CoverTrafficConfig { enabled: bool }` with `CoverTrafficConfig { tier: CoverTrafficTier }`. Four tiers: `full` (30s/1024B — maximum metadata privacy), `reduced` (120s/256B — battery-conscious), `off` (constrained devices, push-wake connections), `custom` (user-specified interval and padding). `CoverTrafficTier::from_profile()` maps profiles to their default tier. No backward compatibility shim — SCP has not shipped.

**Connection pooling** (§10.13.2): Explicitly specify that a single adapter connection to a relay is shared by all contexts assigned to that relay. `TransportManager` maintains at most one connection per relay URL. Cross-`TransportManager` sharing via `Arc<ConnectionPool>` keyed by `(relay_url, transport_type)`.

**Connection budget** (§10.13.3): Maximum total connections across all adapters, derived from profile. When budget is reached, least-recently-used connections are closed and subscriptions migrated. Mobile profile sheds connections for inactive contexts, relying on push notification bridge (§10.7) to wake on new messages.

**Suppression resistance trade-offs:** `mobile` accepts 2-relay minimum (reduced suppression detection). `constrained` accepts 1-relay minimum (no suppression detection). Both are explicit, documented trade-offs — acceptable because mobile devices are typically behind gateways with full-profile connectivity, and constrained devices are behind gateway agents that participate in full-profile contexts.

### Rationale

- **Profiles over per-setting configuration:** Bundling related transport parameters into named profiles prevents misconfigurations (e.g., setting cover traffic to "full" with a connection budget of 2). A profile guarantees internally consistent transport behavior.
- **Four profiles, not three or five:** `server` and `desktop` differ only in connection budget and are both persistent-connection models. `mobile` is the inflection point — it introduces push-wake semantics and reduced cover traffic. `constrained` is fundamentally different — connectionless, poll-based, no cover traffic. These four cover the real device-class spectrum without artificial granularity.
- **No backward compat for CoverTrafficConfig:** SCP has not shipped. The `enabled: bool` field was a placeholder. Refactoring to `tier: CoverTrafficTier` is strictly better — no migration, no shim, no technical debt.
- **Explicit suppression trade-offs:** Hiding the security implications of reduced relay counts would violate the legibility tenet. Documenting them in the spec makes them informed decisions, not silent degradation.

### Rejected Alternatives

1. **Automatic profile switching based on battery level.** Over-engineered — the application knows its device class at initialization. Dynamic switching mid-session would require re-negotiating relay assignments and cover traffic parameters, adding protocol complexity for a marginal benefit.
2. **Per-context profiles.** Would allow a single device to run some contexts at "server" and others at "constrained." This complicates connection budgeting and creates confusing UX. The profile applies to the device, not the context. If a specific context needs different transport behavior, override individual settings rather than mixing profiles.
3. **Six-tier cover traffic.** Early design had `full`, `high`, `medium`, `low`, `minimal`, `off`. Four tiers (plus `custom`) are sufficient — `full` and `reduced` cover the real-world cases, `off` covers constrained, and `custom` covers everything else.

### Dependencies

- **ADR-004 (Native Relay):** Cover traffic implementation, subscription registry, PING/PONG keepalive.
- **§9.10.6 (Cover Traffic):** Amended specification that this ADR implements.
- **§10.13 (Transport Profiles):** Specification that this ADR implements.
- **§10.7 (Push Notification Bridge):** Mobile profile relies on push-wake for inactive context delivery.

### Acceptance Criteria

1. **`TransportProfile` enum** with `Server`, `Desktop`, `Mobile`, `Constrained` variants. Each variant carries default values for `min_relays`, `max_connections`, `reconnect_backoff_range`, and `cover_traffic_tier`. Platform inference via `#[cfg(target_os)]` with runtime refinement for Linux (server/constrained/desktop heuristics per §10.13.1).
2. **`CoverTrafficTier` enum** with `Full`, `Reduced`, `Off`, `Custom { interval: Duration, padding_bytes: usize }` variants. `CoverTrafficConfig` uses `tier: CoverTrafficTier` instead of `enabled: bool`. `from_profile()` method maps profile to tier. All existing callers updated.
3. **`ConnectionPool`** keyed by `(relay_url, transport_type)`. `TransportManager` uses the pool for adapter lookup and reuse. Single connection per relay per transport type. `Arc<ConnectionPool>` for cross-manager sharing.
4. **Connection budget enforcement.** `TransportManager` tracks total active connections. When `max_connections` exceeded, LRU connection is closed. Subscriptions on evicted connections are migrated to surviving connections to the same relay, or trigger relay reassignment.
5. **`TransportConfig` gains `profile: TransportProfile` field.** Existing `TransportConfig` construction sites updated. Profile defaults apply unless overridden.

### Scope

**New files:**

| File | Purpose |
|------|---------|
| `crates/scp-transport/src/pool.rs` | `ConnectionPool` keyed by `(relay_url, transport_type)`, LRU eviction |
| `crates/scp-transport/src/profile.rs` | `TransportProfile` enum, platform inference, default mappings |

**Modified files:**

| File | Change |
|------|--------|
| `crates/scp-transport/src/config.rs` | Add `profile: TransportProfile` to `TransportConfig`. Add `CoverTrafficTier` enum, refactor `CoverTrafficConfig`. |
| `crates/scp-transport/src/cover_traffic.rs` | Use `CoverTrafficTier` for interval/padding selection. Remove boolean `enabled` paths. |
| `crates/scp-transport/src/manager.rs` | Use `ConnectionPool` for adapter lookup. Enforce connection budget. Profile-aware defaults. |
| `crates/scp-transport/src/lib.rs` | Re-export new types. |

**Estimated functions:** ~15-20 public functions, ~10-12 internal helpers.

---

## ADR-037: Alternative Transport Bindings (QUIC, WebTransport, UDP/DTLS)

**Status:** Decided

### Context

SCP's transport layer is designed around the `TransportAdapter` trait (ADR-005), which abstracts the wire protocol behind five methods (`send`, `subscribe`, `unsubscribe`, `query`, `delete`). The only fully implemented adapter is the native relay using MessagePack-over-WebSocket (ADR-004). While functional, WebSocket has limitations that matter at scale:

1. **Head-of-line blocking.** WebSocket is a single ordered stream over TCP. A slow or lost packet blocks all subsequent frames — including frames for unrelated contexts multiplexed on the same connection. This is a fundamental TCP limitation.
2. **No connection migration.** When a mobile device switches from Wi-Fi to cellular, the TCP connection breaks. The client must fully reconnect and re-subscribe — losing messages during the transition.
3. **Keepalive overhead.** WebSocket requires application-level PING/PONG (30s interval per ADR-004). Each ping is a round trip on the wire, separate from the transport-layer keepalive.
4. **Browser transport ceiling.** Browsers are limited to WebSocket for bidirectional streaming. WebSocket over HTTP/1.1 doesn't benefit from HTTP/2 multiplexing or HTTP/3 (QUIC). The WebTransport API gives browsers access to QUIC-like semantics (independent streams, datagrams) over HTTP/3.
5. **IoT exclusion.** Constrained devices (§10.16) that operate on UDP-based duty cycles cannot use WebSocket at all.

### Decision

Spec and implement three new Tier 1 transport bindings, all using the same MessagePack wire format defined in ADR-004.

#### QUIC Transport Binding (§10.14)

QUIC replaces WebSocket for native (non-browser) clients. One QUIC connection per relay replaces one WebSocket per relay. SCP operations map to per-operation QUIC streams:

| Operation | QUIC mapping |
|-----------|-------------|
| PUBLISH | New bidirectional stream → send → ACK → close |
| SUBSCRIBE | Long-lived bidirectional stream → receive BLOBs until unsubscribe |
| UNSUBSCRIBE | Close the subscription's stream (clean FIN) |
| QUERY | New bidirectional stream → send → results + query_complete → close |
| DELETE | New bidirectional stream → send → ACK → close |
| PING/PONG | Not needed — QUIC native keepalive (PATH_CHALLENGE/PATH_RESPONSE) |

Benefits: 0-RTT reconnect (session tickets), connection migration (IP change without reconnect), no head-of-line blocking (independent streams), no PING/PONG overhead, no `ref_id` correlation (responses scoped to their stream).

Relay advertises QUIC via `.well-known/scp` `relay_config.transports` array. Client probes QUIC first, falls back to WebSocket on timeout.

#### WebTransport Binding (§10.15)

WebTransport is the browser-facing equivalent of QUIC. The WASM binding uses the browser's `WebTransport` API over HTTP/3. Server-side, relay handles both QUIC and WebTransport sessions — they're both QUIC underneath.

Fallback chain: WebTransport → WebSocket → error. The WASM binding attempts WebTransport first, falls back to WebSocket when the `WebTransport` API is unavailable or connection fails.

HTTP/3 is also the relay's HTTP upgrade path for all endpoints (`.well-known/scp`, dev API, broadcast projection), advertised via `Alt-Svc` header and ALPN negotiation.

#### UDP/DTLS Binding (§10.16)

For IoT and constrained devices that cannot sustain TCP connections. Two options:

- **MessagePack-over-DTLS:** SCP-native, connectionless DTLS 1.3 datagrams, same wire format as ADR-004. Session resumption via DTLS session tickets.
- **CoAP-over-DTLS:** IoT interop, CoAP (RFC 7252) as framing layer. Maps SCP operations to CoAP methods (POST→PUBLISH, GET→QUERY, DELETE→DELETE). CoAP Observe (RFC 7641) for lightweight subscription.

Both options: no persistent subscriptions (poll via QUERY), no cover traffic, single relay, MTU-constrained blob size.

### Rationale

- **QUIC over HTTP/2:** HTTP/2 multiplexing solves head-of-line blocking at the HTTP layer but not at TCP. QUIC solves it at the transport layer. HTTP/2 also doesn't provide connection migration.
- **Per-operation streams over single-stream emulation:** Running the same single-stream protocol over QUIC (as some WebSocket-to-QUIC migrations do) wastes QUIC's stream model. Per-operation streams eliminate `ref_id` correlation, enable natural flow control per operation, and make subscribe/unsubscribe map cleanly to stream lifecycle.
- **WebTransport over raw QUIC in browser:** Browsers don't expose raw QUIC sockets. WebTransport is the standardized API for QUIC-like semantics in browsers. Server-side, it's the same QUIC stack.
- **Two constrained options over one:** MessagePack-over-DTLS is simpler and native to SCP. CoAP-over-DTLS enables interop with existing IoT infrastructure (LwM2M, CoAP proxies). Different IoT ecosystems prefer different approaches.
- **Same wire format across all bindings:** All four Tier 1 adapters use ADR-004's MessagePack wire format. The only differences are framing (WebSocket frames vs. QUIC streams vs. DTLS datagrams vs. CoAP messages) and connection lifecycle. This means the relay's blob storage, subscription registry, and authentication are shared across all transports.

### Rejected Alternatives

1. **gRPC-based transport.** gRPC provides strong typing and streaming but adds a Protobuf dependency, doesn't support connection migration, and doesn't solve head-of-line blocking (it runs on HTTP/2 over TCP). Also doesn't work in constrained environments.
2. **Custom UDP protocol without DTLS.** SCP requires transport encryption (§9.9). Rolling a custom encryption layer over raw UDP would be security-critical code with no review history. DTLS is standardized and audited.
3. **WebSocket-only with proxy-based QUIC.** A QUIC-to-WebSocket proxy at the relay would give clients QUIC benefits for the first hop but still suffer TCP limitations at the relay. End-to-end QUIC is strictly better.
4. **MQTT as the constrained device transport.** MQTT is a good fit for IoT pub/sub but adds a broker dependency and doesn't provide the connectionless semantics that truly constrained devices need. MQTT is available as a Tier 2 adapter (§10.5.2) for environments where a broker already exists.

### Dependencies

- **ADR-004 (Native Relay):** MessagePack wire format, relay operations (PUBLISH/SUBSCRIBE/QUERY/DELETE), blob storage, subscription registry.
- **ADR-005 (Transport Trait):** `TransportAdapter` trait that all bindings implement.
- **ADR-036 (Transport Profiles):** Profile-aware connection behavior, cover traffic tiers.
- **§10.14 (QUIC Transport Binding):** Specification for QUIC adapter.
- **§10.15 (HTTP/3 and WebTransport):** Specification for HTTP/3 and WebTransport.
- **§10.16 (Constrained Device Transport):** Specification for UDP/DTLS adapters.

### Acceptance Criteria

1. **`QuicAdapter` implements `TransportAdapter`.** Uses `quinn` crate. Per-operation bidirectional streams for PUBLISH/QUERY/DELETE. Long-lived bidirectional stream for SUBSCRIBE. Same MessagePack wire format as ADR-004. Passes `transport_conformance!()`.
2. **QUIC connection lifecycle.** 0-RTT resumption via session tickets. Connection migration on IP change. Profile-aware reconnect backoff. QUIC native keepalive replaces PING/PONG.
3. **Relay multi-transport listener.** `RelayServer` accepts WebSocket, QUIC, and WebTransport connections. ALPN negotiation. Shared subscription registry and blob storage across all transport handlers.
4. **WebTransport server-side session handling.** Relay accepts WebTransport sessions at `/scp/v1`. Streams map to SCP operations (same model as QUIC). HTTP/3 served via ALPN on TLS port. `Alt-Svc` header advertises HTTP/3.
5. **`UdpDtlsAdapter` implements `TransportAdapter`.** DTLS 1.3 session management. Connectionless PUBLISH/QUERY/DELETE as DTLS datagrams. `subscribe()` returns error (not supported — poll via QUERY). Session resumption via DTLS session tickets. Passes `transport_conformance!()` for supported operations.
6. **`.well-known/scp` transport advertisement.** `relay_config.transports` array lists all supported transport types. Relay auto-detects based on enabled listeners.

### Scope

**New files:**

| File | Purpose |
|------|---------|
| `crates/scp-transport/src/quic/mod.rs` | QUIC adapter module |
| `crates/scp-transport/src/quic/adapter.rs` | `QuicAdapter` implementing `TransportAdapter` |
| `crates/scp-transport/src/quic/streams.rs` | Per-operation stream management |
| `crates/scp-transport/src/quic/connection.rs` | Connection lifecycle (0-RTT, migration, reconnect) |
| `crates/scp-transport/src/quic/listener.rs` | Relay-side QUIC listener |
| `crates/scp-transport/src/webtransport/mod.rs` | WebTransport adapter module |
| `crates/scp-transport/src/webtransport/session.rs` | Server-side WebTransport session handling |
| `crates/scp-transport/src/webtransport/adapter.rs` | Client-side WebTransport adapter (WASM) |
| `crates/scp-transport/src/udp/mod.rs` | UDP/DTLS adapter module |
| `crates/scp-transport/src/udp/adapter.rs` | `UdpDtlsAdapter` implementing `TransportAdapter` |
| `crates/scp-transport/src/udp/coap.rs` | CoAP-over-DTLS framing |
| `crates/scp-transport/src/udp/listener.rs` | Relay-side UDP/DTLS listener |

**Modified files:**

| File | Change |
|------|--------|
| `crates/scp-transport/Cargo.toml` | Add `quinn` (feature = "quic"), DTLS crate (feature = "udp"), CoAP crate (feature = "coap") |
| `crates/scp-transport/src/lib.rs` | Re-export new adapter modules |
| `crates/scp-transport/src/native/server.rs` | Multi-transport listener (WebSocket + QUIC + WebTransport + UDP/DTLS) |
| `crates/scp-node/src/well_known.rs` | `transports` field in `.well-known/scp` response |
| `crates/scp-node/src/http.rs` | HTTP/3 via ALPN, `Alt-Svc` header |
| `crates/scp-ffi/wasm/src/transport.rs` | WebTransport API usage with WebSocket fallback |

**Estimated functions:** ~40-50 public functions, ~30-40 internal helpers across all new and modified files.

---

## ADR-040: Streaming BlobStore API

**Status:** Accepted
**Closes:** #269

### Context

The `BlobStorage` trait requires full `Vec<u8>` materialization for all blob operations. This is a bottleneck for large blobs (video, voice, file transfers) — streaming is a core protocol competency, and all transport layers already support it. The storage layer is the only component that forces full materialization.

### Decision

Add streaming variants (`store_streaming`, `get_streaming`) to `BlobStorage` with **default implementations** that delegate to the existing `Vec<u8>` methods. This is fully additive — no existing method signatures change, no existing implementations break.

Key design choices:

- **`Stream<Item = Result<Bytes, StorageError>>` over `AsyncRead`** — matches the `futures::Stream` ecosystem used throughout the codebase (tokio-tungstenite, h3, aws-sdk-s3). No adapter conversion needed at call sites.
- **Split return (`BlobMetadata` + `BlobBodyStream`)** — metadata is available immediately; body can be forwarded without waiting for full consumption.
- **`Option<u64>` content length** — hint for pre-allocation, not a security boundary.
- **Default implementations** — all 7 existing backends work immediately. Only S3 gets a native override initially; others can be optimized without trait changes.
- **Caller-provided blob_id** — the relay computes SHA-256 incrementally as it receives the blob over the wire. The storage layer trusts the relay's computation (same trust model as today).

### Alternatives Considered

1. **Replace `Vec<u8>` methods with streaming-only** — breaks all 7 implementations and all call sites simultaneously. Massive blast radius for no benefit (the `Vec<u8>` path is still correct for small blobs).
2. **`AsyncRead + AsyncWrite`** — requires `tokio::io` adapters at every boundary. The codebase uses `Stream`-based patterns throughout.
3. **Chunk-based API (`store_chunk`/`finalize`)** — complex state machine, partial-upload cleanup, resumable upload complexity. Over-engineered for the current need.

### Consequences

- All existing backends work via defaults. Zero breaking changes.
- S3 backend can stream multi-GB blobs without memory pressure.
- Future backends (e.g., PostgreSQL large objects) can override defaults when ready.
- Current wire protocol delivers blobs as single MessagePack-framed messages (already materialized in memory), so streaming call sites provide no benefit until chunked wire delivery exists. The streaming storage API is complete — it serves developers building chunked delivery.

---

## ADR-042: Broadcast Content Delivery

**Status:** Decided

### Context

Broadcast projection (§18.11, ADR-035) serves decrypted broadcast messages over HTTP as JSON. This enables CDN distribution and feed consumption, but stops short of serving structured web content. A simple text+image website cannot be served from a broadcast context today because:

1. **No content metadata on messages** — `BroadcastEnvelope` has no `content_type` or `path` field. Content is opaque `Vec<u8>`.
2. **No path-based routing** — projection endpoints are blob-ID-addressed only (`/messages/<blob_id>`), not path-addressed (`/about`, `/styles.css`).
3. **No MIME-aware serving** — projection always returns `application/json` regardless of content type.
4. **No atomic deploys** — no concept of a versioned set of assets that can be swapped atomically.
5. **No SDK convenience** — no `broadcastPublishAssets(dir)` or asset-level publish methods.

### Decision

Extend broadcast projection into a full content delivery layer by defining `BroadcastContent` as the canonical structured inner payload (inside `encrypted_content`, after decryption). The relay wire format (`BroadcastEnvelope`) is unchanged — relays continue to see opaque ciphertext.

Key design choices:

- **Magic byte prefix for version detection.** ASCII `"SCP"` + `version_u8` prefix on the decrypted inner payload. After AES-256-GCM decryption, check first 3 bytes for `BROADCAST_CONTENT_MAGIC`. If matched, read 4th byte as version and deserialize remaining bytes as MessagePack `BroadcastContent`. Legacy payloads (no magic prefix) are treated as raw bytes. Zero false-positive rate — legacy encrypted payloads will not start with "SCP" unless deliberately crafted.
- **Deploy manifest blob for persistence.** A special broadcast message containing the complete `path -> blob_id` mapping for a deploy. Loaded on `enable_broadcast_projection()` to rebuild path index on node restart. Solves persistence, recovery, and dedup in one mechanism.
- **`ArcSwap` per-context for lock-free concurrent reads.** `Arc<ArcSwap<PathIndex>>` per `ProjectedContext` — NOT on the shared `projected_contexts` registry lock. HTTP handlers read the current deploy via `ArcSwap::load()`. Index is built at commit time only (not during per-asset publish). Per-asset publish requires no write locks on the registry.
- **Node-local `SiteConfig`.** Site configuration (hostname, index path, resource limits, CSP override) is passed to `enable_broadcast_projection()`. NOT part of governance-governed `ProjectionPolicy` — deployment concerns stay out of governance.
- **Required security headers.** All site responses include `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `Cross-Origin-Opener-Policy: same-origin`, `Referrer-Policy: same-origin`. Each projected context MUST have its own hostname/subdomain for origin isolation.
- **Cache behavior.** Content-hashed paths get immutable 1-year cache. Non-hashed paths get `max-age=0, must-revalidate` with ETag for CDN revalidation. 404 responses get `Cache-Control: no-store`.

### Rationale

- **Structured inner payload:** The relay stays dumb — content structure is a post-decryption concern. Putting metadata in the outer `BroadcastEnvelope` would violate the relay capability ceiling (§9.9.1).
- **Magic byte prefix over heuristic detection:** MessagePack markers have a ~10% collision rate on arbitrary payloads and create a parsing oracle. A 3-byte ASCII prefix ("SCP") has zero false positives against non-crafted legacy payloads.
- **Deploy manifest blob:** Solves persistence, recovery, and dedup in one mechanism. Without it, the path index is lost on node restart and must be reconstructed by scanning all blobs — expensive and fragile.
- **`ArcSwap` per-context:** Eliminates registry lock contention during batch publish. HTTP read handlers are completely lock-free; publish operations only touch per-context state.
- **Node-local `SiteConfig`:** Hostname binding, index path, and resource limits are deployment concerns that vary per node. Including them in governance-governed `ProjectionPolicy` would require governance actions to change a DNS mapping — inappropriate coupling.

### Rejected Alternatives

1. **Cleartext metadata on `BroadcastEnvelope`.** Would expose content paths and MIME types to relays, violating the relay capability ceiling (§9.9.1). Relays must not learn content structure.
2. **Heuristic version detection via MessagePack markers.** First-byte heuristics on MessagePack payloads have a ~10% collision rate and create a parsing oracle (attacker-controlled payloads could trigger version misparsing). Magic byte prefix is unambiguous.
3. **In-memory-only path index without manifest.** Path index is lost on node restart. Reconstructing from a blob scan is expensive (enumerate all blobs, decrypt each, extract metadata) and fragile (relies on blob TTL not having expired). The manifest blob makes restart recovery O(1).
4. **SPA fallback in v1.** Introduces security edge cases: CDN 404 caching serves the SPA shell for paths that don't exist (information disclosure), and distinguishing "route not found" from "asset not found" requires application-level routing knowledge the node doesn't have. SPA routing is a deployment convenience, not a protocol concern. Users who need it put a reverse proxy in front. Can be added later without breaking changes.
5. **`ContentEncoding` enum in v1.** Pre-compressed content adds complexity (negotiation, double-compression risk, per-asset encoding tracking) for minimal benefit — tower-http handles on-the-fly compression transparently for HTTP responses.
6. **Staged deploy API with typestate.** A `DeployBuilder` with typestate transitions (`Publishing` → `Committing` → `Live`) adds API complexity without safety benefit — the batch publish pattern (publish all assets, then commit) is simpler and already atomic at the commit boundary.

### Dependencies

- **ADR-035 (Local HTTP Control API and Broadcast Projection):** `ProjectedContext` type, projection endpoint composition, `NodeState` extensions, `Arc<dyn BlobStorage>` sharing.
- **§5.14 (Broadcast Contexts):** `BroadcastEnvelope`, `BroadcastKey`, `BroadcastAdmission`, per-author AES-256 keys, `routing_id` derivation.
- **§18.11 (HTTP Broadcast Projection):** Feed endpoint, per-message endpoint, decryption architecture, security properties, SDK surface.

### Acceptance Criteria

1. **`BroadcastContent` struct** with `version: u8`, `metadata: ContentMetadata`, `body: Vec<u8>`. Wire format: `BROADCAST_CONTENT_MAGIC ++ version_u8 ++ MessagePack(BroadcastContent)`.
2. **`ContentMetadata` struct** with `path: Option<ContentPath>`, `content_type: Option<MimeType>`, `deploy_id: Option<String>`, `etag: Option<String>`.
3. **`ContentPath` newtype** rejects `..`, `//`, `./`, `\`, null bytes, control chars, non-UTF-8, percent-encoded traversals, query strings, fragments. Enforces leading `/`, max 1024 bytes, no trailing slash (except root `/`). Case-sensitive.
4. **`MimeType` newtype** matches `type/subtype` grammar (RFC 7231 §3.1.1.1). Rejects CRLF and control characters.
5. **`deserialize_broadcast_content()`** implements version detection algorithm: check magic prefix, read version byte, deserialize MessagePack. Legacy payloads (no magic prefix) returned as raw bytes.
6. **Path-based projection endpoint** at `/scp/broadcast/<routing_id>/site/<path>` resolves path to blob in current deploy, returns raw body with declared `Content-Type`.
7. **Virtual host routing** via `SiteConfig.hostname` — requests to the configured hostname resolve directly to the context's path index.
8. **Security headers** on all site responses: `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, `X-Frame-Options: DENY`, `Strict-Transport-Security: max-age=63072000; includeSubDomains`, `Cross-Origin-Opener-Policy: same-origin`, `Referrer-Policy: same-origin`.
9. **Atomic deploy commit** builds immutable `PathIndex`, stores deploy manifest blob, swaps `current_deploy_id` via `ArcSwap`.
10. **Deploy retention** keeps current + previous indexes in memory. Configurable retention count (default 2).
11. **Deploy manifest blob** persists `path -> blob_id` mapping. Loaded on `enable_broadcast_projection()` for restart recovery.
12. **`SiteConfig` struct** with `hostname`, `index_path`, `max_assets_per_deploy`, `max_deploy_size_bytes`, `deploy_retention_count`, `csp_override`. Validated on assignment.
13. **`broadcastPublishAsset` and `broadcastPublishAssets`** SDK methods across all FFI bridges. Typed `AssetEntry` parameter. Returns `{ blobId, etag }`. Content-hash dedup.
14. **Resource limits enforced:** max 10,000 assets per deploy, max 512 MiB total deploy size, max 8 deploys retained per projected context.

### Scope

**New files:**

| File | Purpose |
|------|---------|
| `crates/scp-core/src/context/broadcast_content.rs` | `BroadcastContent`, `ContentMetadata`, `ContentPath`, `MimeType`, magic byte prefix, `deserialize_broadcast_content()` |

**Modified files:**

| File | Change |
|------|--------|
| `crates/scp-node/src/projection.rs` | Path index (`ArcSwap`), `/site/<path>` endpoint, MIME-aware serving, deploy manifest, security headers |
| `crates/scp-node/src/http.rs` | Wire `/site/` route, virtual host routing |
| `crates/scp-node/src/lib.rs` | `SiteConfig`, deploy management, manifest persistence |
| `crates/scp-ffi/src/context.rs` | PyO3 bridge exports for `broadcastPublishAsset`, `broadcastPublishAssets` |
| `crates/scp-ffi/napi/src/context.rs` | NAPI bridge exports |
| `crates/scp-ffi/uniffi/src/bridge.rs` | UniFFI bridge exports |
| `crates/scp-ffi/wasm/src/context.rs` | WASM bridge exports (`ContentPath`/`MimeType` validation reimplemented locally per ADR-034) |
| `bindings/typescript/src/context.ts` | `broadcastPublishAsset`, `broadcastPublishAssets` |
| `bindings/python/scp_sdk/context.py` | `broadcast_publish_asset`, `broadcast_publish_assets` |

**Estimated functions:** ~20-25 public functions, ~15-20 internal helpers across all files.
