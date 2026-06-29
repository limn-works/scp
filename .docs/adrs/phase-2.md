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
   - Emits a `MessageSent` `ContextEvent`. Per-author application activity is a
     local signal, not a canonical Merkle leaf, until ADR-051's causal-DAG
     ordering — see the ADR-011 amendment, exclusion taxonomy §2.

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
    Custom(String),               // Context-specific custom capability. As a ceiling
                                  // entry it MUST be well-formed `{resource}:{action}`
                                  // or an explicit `{resource}:*` wildcard (spec §5.3.1.1).
}
```

   **Mode-agnostic capabilities.** `MessagesRead` and `MessagesWrite` apply to both Encrypted and Broadcast modes. The abstract capability to read/write in a context is independent of the encryption pipeline — `ContextMode` determines processing, not authorization. No new capability variants are needed for broadcast mode.

   - Ceiling is set at context creation via `ContextParams.ceiling`.
   - Ceiling mutability is determined by `ContextParams.ceiling_policy` (ADR-008): `Immutable` (default) returns `ContextError::CeilingImmutable` on modification; `Governed` allows modification through the context's governance model.
   - Role permission sets are validated against the ceiling at role definition time. A role cannot grant capabilities outside the ceiling.
   - Every ceiling entry is validated for well-formedness at context creation (spec §5.3.1.1 is authoritative for the charset): a built-in category, a `{resource}:{action}` custom capability, or an explicit `{resource}:*` wildcard. `{resource}` and `{action}` are non-empty kebab-case tokens separated by exactly one colon; the asterisk is permitted only as the whole action segment of a `{resource}:*` wildcard — never in the resource position and never as a substring (so `*:*` and `*:read` are malformed, not an all-resources grant). A `Custom` entry with no action segment (a bare single token, e.g. `payments`) is malformed and rejected with `InvalidCeilingCategory` — it is never silently widened to a wildcard. A custom entry is also rejected if it names a built-in capability under any spelling — enforced by canonical resolution: an entry is admitted as a custom only if resolving its string through the canonical capability parser does not yield a built-in (spec §5.3.1.1's no-collision rule). A custom `{resource}:*` wildcard is additionally rejected when `{resource}` is the resource token of any built-in capability (e.g. `member:*`, `governance:*`): canonical resolution does not catch it (no `member:*` built-in exists) but ceiling wildcard coverage would let it silently grant the privileged built-in actions in that family (e.g. `member:ban`) — closed by construction over the built-in resource-token set (spec §5.3.1.1's "No built-in-resource wildcard shadow" rule); a non-wildcard custom action under a built-in resource (e.g. `member:promote`) and a wildcard over a non-built-in resource (e.g. `payments:*`) both remain valid. Ceiling-entry strings are subject to the §9.1A string sanitization and the 256-byte length cap for context string fields (§9.1A "String field validation" table in spec §5.9).

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
   - `subscriber` — `MessagesRead` only. In open broadcast contexts (`public-broadcast` template), `MessagesRead` is auto-granted on DID-authenticated registration, following the context reader-tier pattern (§6.2.2B). In gated broadcast contexts (`gated-broadcast` template), `MessagesRead` requires an explicit admin-issued UCAN.

   The auto-grant subscriber pattern extends the context two-tier model — it is not a new primitive.

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
   8. **Ceiling** — Verify every capability the token grants is within the context's immutable capability ceiling — not only the invoked `required_capability`. The token's entire attestation set (`att`) is checked; a token carrying any out-of-ceiling attestation is rejected even if the invoked capability is itself within the ceiling.
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
- **ADR-003 (DID):** Events are signed by the acting agent's DID. The verification method that signed an event (`"#active"` or `"#agent"`, ADR-039) is carried by the signature apparatus, **not** as a field on the `Event` struct — the canonical `scp_event_log::Event` has seven fields (`event_type`, `actor_did`, `timestamp`, `sequence`, `payload`, `prev_hash`, `signature`) and no `signing_key_id`. A verifier resolves the correct public key from the actor's DID document exactly as it does for any other Ed25519 signature in the protocol (see the signing-key-identification note in criterion 1). Checkpoint signatures are verified against DID public keys.

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
    pub timestamp: u64,
    pub sequence: u64,              // Monotonic event sequence within this log
    pub payload: EventPayload,      // Type-specific data
    pub prev_hash: [u8; 32],        // Hash of the previous event (hash chain)
    pub signature: Ed25519Signature,
}
```

   **Signing-key identification (ADR-039).** The verification method that signed
   an event (`"#active"` or `"#agent"`) is carried by the credential / signature
   apparatus, **not** as a struct field on `Event`. The canonical
   `scp_event_log::Event` type has no `signing_key_id` field; a verifier resolves
   the correct public key from the actor's DID document the same way it does for
   any other Ed25519 signature in the protocol. (The `signing_key_id` parameter
   on `generate_checkpoint` in criterion 8 is a *checkpoint*-signing argument and
   is unaffected.)

   **Timestamp assignment (committer-assigned, copied by every member).** The
   `timestamp` field is convergent by *assignment*, parallel to `sequence`: for a
   commit-ordered event the committing member sets it to the `created_at` of the signed
   SCP envelope carrying the commit (§9.8.2), and every member copies that one value
   into its own leaf. Because all members hold the identical committed value, the leaf
   is agreed by all of them — it is byte-identical across honest members (so the §9.9.3
   equal-count/equal-root test stays sound), tamper-evident (covered by the committer's
   envelope signature and the leaf hash), and bounded to real time within the ±5-minute
   future skew tolerance of §9.8.2. The one thing members do *not* agree on is their
   private physical clocks, which is precisely why a per-member local `now()` reading is
   wrong here: there is no single such reading to agree on. This is the same convergence
   principle stated for derived records in the amendment below (a field is convergent iff
   its source is convergent): the source here is one signed envelope timestamp, not N
   local clocks. For the timer-triggered events that carry no
   commit envelope (TTL expiry/close, governance-freeze expiry, deferred
   economic-policy application), the convergent `timestamp` is the pre-computed
   deadline already held in convergent context state (the TTL deadline, the
   freeze-expiry instant, the policy-application time), never local `now()` — for the
   same reason velocity/rate-triggered consequences are excluded (a wall clock the
   protocol neither has nor needs). The leaf timestamp's convergence does not make it
   authoritative over log *order* (§9.8.3): the Merkle order is the orderer; the
   timestamp is a convergent, bounded annotation carried on that order.

```rust
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
    MessageSent,                  // per-author application activity; convergent canonical leaf in the ADR-051 end state, local ContextEvent until then
    ToolRegistered,
    ToolUpdated,
    ToolInvoked,                  // per-author application activity; see MessageSent (ADR-051 causal-DAG ordering)
    ToolVerified,
    ToolInterfaceEstablished,
    GovernanceAction,
    ConsistencyCheckpoint,
    AbsenceProofRequested,
    MemberBlocked,          // ADR-007: Signed block notification recorded for auditability
    KeyEpochAdvance,        // ADR-007: Sender key epoch rotation (shared across Encrypted and Broadcast modes)
    MediaSessionStarted,    // ADR-024: media session start
    MediaSessionEnded,      // ADR-024: media session end
    PaymentReceived,        // §19.6.1: payment captured
    EconomicPolicyChanged,  // §19.3: economic policy change proposed (24h notice start)
    EconomicPolicyApplied,  // §19.3: pending economic policy change applied
    SpendingUcanGranted,    // §19.6.1: spending UCAN granted
    SpendingUcanRevoked,    // §19.6.1: spending UCAN revoked
    // Governance event types (ADR-031 §8)
    GovernanceProposalCreated,
    GovernanceVoteCast,
    GovernanceVoteWithdrawn,
    GovernanceProposalResolved,
    GovernanceConflictDetected,
    GovernanceConflictResolved,
    GovernanceDeadlockRecovery,
    GovernanceActionExecuted,
    // Provenance event types (§7.3, issue #586)
    ProvenanceAttached,
    ProvenanceReceived,
    // Governance-action-coverage event types (native↔WASM unification; see the
    // Amendment below). Each traces to a GovernanceAction (ADR-031 §2) or a
    // §19 / §5.11A / §9.9 protocol action.
    AdminTransferred,             // TransferAdmin
    CeilingModified,              // ModifyCeiling applied
    CeilingModificationPending,   // ModifyCeiling delay-window start
    ThresholdModified,            // ModifyThreshold §4b
    SignerAdded,                  // AddSigner §4b
    SignerRemoved,                // RemoveSigner §4b
    ChildContextCreated,          // CreateChildContext §5.13; consumed by §7 trust
    ContextPromoted,              // PromoteContext §5.10
    ContentKeysRotated,           // RotateContentKeys §9.17/ADR-038
    MemberReset,                  // ResetMember ADR-029 Tier-3; §23 reset
    MemberSuspended,              // SuspendCapability
    MemberSuspendedAll,           // SuspendAccess
    MemberUnblocked,              // ADR-007 block reversal; pairs with MemberBlocked
    AccessRestored,               // RestoreAccess §5 ReadAccessRestored
    GovernanceReconfigured,       // ReconfigureGovernance §10
    GovernanceFreezeExpired,      // §7 conflict-freeze exit
    HardRateLimitModified,        // ModifyHardRateLimit §19.7 D4
    EconomicPolicyLocked,         // LockEconomicPolicy §19.3
    ContextMigrationStarted,      // ProposeContextMigration §5.11A grace start
    ToolRemoved,                  // RemoveTool; pairs with ToolRegistered
    PruningPolicyModified,        // ModifyPruningPolicy ADR-030 §6
    CommitBroadcasted,            // MLS commit broadcast record §9.9 reconciliation
    CommitBroadcastPending,       // deferred-commit queue record
    // (PseudonymAnnounced is NOT a durable EventType — see the exclusion list below.)
    // Lifecycle / migration event types (ADR-049 §9; §5.11A). Parameters live
    // in EventPayload, never in the type name.
    ContextTombstoned,            // §5.11A.5 terminal migration; payload: destination_id, migration_proposal_id (actor_did = "system")
    ContextMigrationCancelled,    // §5.11A migration abort; pairs with ContextMigrationStarted; payload: original_proposal_id
    TtlExtended,                  // §5.10 unanimous TTL extension; payload: old_deadline_unix, new_deadline_unix, proposal_id, consenting_members
    TtlExtensionRejected,         // §5.10 TTL extension denied; payload: proposal_id, rejecting_members
    // Content-access governance event types (ADR-031 §3; §5). Pairs with the
    // existing AccessRestored variant.
    AccessRevoked,                // RevokeReadAccess / RevokeWriteAccess; payload: target_did, scope
    // Economic event types (§19.6.1; ADR-031 §3).
    SpendApproved,                // ApproveSpend governance action; payload: spender, amount, purpose
    PaymentCaptureFailed,         // §19.6.1 payment capture failure record; payload: cost and capture-failure detail
    // Consequence-enforcement event types (ADR phase-4 trust engine; §7.3.7).
    // actor_did = the consequence-enforcement system actor.
    ConsequenceTriggered,         // §7.3.7 rule trigger fired; payload: member_did, rule_index, trigger_kind, action_type
    ConsequenceEnforced,          // §7.3.7 consequence action applied; payload: member_did, rule_index, trigger_kind, action_type
    ConsequenceEnforcementFailed, // §7.3.7 enforcement failed (e.g. member departed mid-flight); payload as above
    ConsequenceEscalatedToSuspendAll, // §7.3.7 failure escalated to SuspendAll; payload as above
    // MLS commit-broadcast reconciliation outcomes (§9.9). Pairs with
    // CommitBroadcasted / CommitBroadcastPending.
    CommitBroadcastSucceeded,     // §9.9.4 deferred commit broadcast succeeded; payload: operation, attempts
    CommitBroadcastFailed,        // §9.9.4 deferred commit broadcast permanently failed; payload: operation, reason, attempts
    // Compromise-recovery event type (§9.12 step 2 "MLS Update in all active
    // contexts"). Distinct from the ADR-007 sender-key KeyEpochAdvance: this
    // records an MLS *group*-epoch advance (Update + self-Commit, broadcast to
    // members) performed during trust recovery. actor_did = "system:recovery".
    RecoveryEpochAdvanced,        // §9.12 step 2 MLS group-epoch advance; payload: old_epoch, new_epoch
    // App-sandbox binding lifecycle (§8; "App binding and unbinding events are
    // visible in the event log"). Parameters live in EventPayload.
    AppBound,                     // §8 app bound to context; payload: app_did, app_name, app_version, capabilities
    AppUnbound,                   // §8 app unbound from context; payload: app_did
}
```

   `EventType` is a closed set with no catch-all variant: every protocol action
   that produces a verifiable history entry in the Merkle event log is one of the
   enumerated variants above. The payment, economic-policy, spending-UCAN,
   governance (ADR-031 §8), and provenance (§7.3) variants reflect types already
   carried by the canonical `scp_event_log::EventType`; the trailing variant
   groups (governance-action coverage, lifecycle/migration per §5.10–§5.11A,
   content-access per §5, economic per §19.6.1, consequence-enforcement per
   §7.3.7, commit-broadcast reconciliation per §9.9.4, compromise recovery per
   §9.12, and app-sandbox binding per §8) were added by the native↔WASM
   unification amendment below.
   The closure obligation spans **every** source that appends to the Merkle log —
   governance actions (ADR-031 §3), lifecycle/migration transitions (ADR-049 §9 /
   §5.11A), membership and access changes (§5), media (ADR-024), economic actions
   (§19), consequence enforcement (phase-4 trust engine / §7.3.7), app-sandbox
   binding (§8), compromise recovery (§9.12 step 2 MLS group-epoch advance), and
   provenance (§7.3) — not governance actions alone. Each new
   variant carries its parameters in `EventPayload`; no parameter is ever baked
   into the type name. The canonical Merkle log carries only **convergent**
   events; per-member-observed emissions are kept out of it (see the convergence
   model and exclusion taxonomy below).

   **Subject-bearing leaf payloads (participation-fact attribution).** The
   participation facts derived from convergent events (§7.3.2) attribute role
   progression and participation duration to the *affected member*, not to the
   governance actor who executed the change. The affected member is therefore
   carried in the leaf `EventPayload`, not inferred from `actor_did` (which, for
   admin-driven joins/removals/assignments, is the admin):

   - `RoleAssigned` carries `RoleAssignedPayload { subject_did: DID, role: RoleName }`.
   - `MemberJoined` / `MemberLeft` carry a membership-change payload
     `{ subject_did: DID, role_name: RoleName }`.

   These three leaves were previously empty-payload leaves. Adding the payload
   changes their leaf preimage (`SHA-256(0x00 ‖ rmp_serde(Event))`) and therefore
   their leaf hash and the resulting Merkle root. This is a **one-way pre-release
   protocol bump** — SCP has no deployed data, so there is no migration: the
   correct end state (subject-bearing payloads) is the only state. The
   `project_payload` projection (in `scp-event-log`) is extended to surface
   `subject_did` from these payloads; any historical empty-payload leaf projects
   `subject_did = None`. No `EventType` variant is added or removed by this change —
   the variant count is unchanged; only the payload contents of three existing
   variants gain a subject DID.

   > **Amendment (native↔WASM event-log unification).** `EventType` is the single
   > canonical event taxonomy across all implementations. The `scp-runtime`
   > provider MUST construct `scp_event_log::Event` values with a typed
   > `event_type` and compute leaves as `SHA-256(0x00 ‖ rmp_serde(Event))` per
   > `tree::append`/`append_unsigned_event` — the free-form-string
   > `EventLogEntry`/`"SCP-EXPORT-ENTRY:"` hash-chain is removed. The checkpoint
   > `merkle_root` (§23.16.1) and the signed-export `event_log_merkle_root`
   > binding (§23.16.8) are the RFC 6962 `tree::root`, NOT the hash-chain head.
   >
   > **Convergence requirement (the §9.9.3 basis).** The canonical Merkle log is
   > the substrate for relay-equivocation detection (§9.9.3): two honest members
   > at the same log position MUST derive the same `tree::root` (equal event count
   > for the totally-ordered commit prefix; equal causally-stable cut / frontier for
   > DAG-ordered application leaves, per ADR-051 §5). The log therefore
   > MUST contain **only convergent events** — those every honest member appends
   > identically and in the same order, i.e. the MLS-commit-ordered stream
   > (governance, membership, lifecycle, role, access, provenance,
   > economic *governance actions* — policy changes, spending-UCAN grants/revocations,
   > compromise recovery, app-binding). Attestations are NOT in this stream — they
   > are credential-layer artifacts (§7.4), not context-log leaves, and there is no
   > `AttestationPublished`/`AttestationRevoked` `EventType` variant.
   > Per-member-observed
   > emissions do not converge and are excluded. The governing rule for the whole
   > trust subsystem: **a derived record is automatic *and* convergent iff its
   > trigger input is convergent.**
   >
   > **Exclusion taxonomy.** Two categories are kept out of the Merkle log:
   >
   > 1. **Local signals (permanent — never an `EventType`).** `MessageReceived`
   >    (a per-recipient observation), `EquivocationDetected` (a local divergence
   >    alert, surfaced as `EquivocationAlert` §23.16.6 / `ContextEvent`), and
   >    `PseudonymAnnounced` (a §9.10.4 routing-bootstrap signal). Each carries its
   >    entire function through an in-process `ContextEvent` buffer notification
   >    plus in-memory state (e.g. the pseudonym-registry `member_did → routing_id`
   >    insert that enables pseudonym-only app-data fan-out) — never a durable leaf.
   >    A durable append would be minted **per receiver, in per-receiver arrival
   >    order** (late joiners never observe earlier ones; the WASM context manager
   >    appends nothing on receive), so no two honest members would converge on the
   >    same `tree::root` — the exact §9.9.3 non-convergence these exclusions guard
   >    against. None has any durable consumer (no checkpoint, export, or proof
   >    reads them). The `scp-runtime` provider previously appended all three; the
   >    unification removes those append sites.
   >
   > 2. **Per-author application activity (interim — canonical in the ADR-051 end
   >    state).** `MessageSent`, `ToolInvoked`, and the payment receipts
   >    `PaymentReceived` / `PaymentCaptureFailed` (appended by the payee on
   >    `adapter.capture()`) are appended only by their author/payee, keyed by a
   >    *per-author* sequence, with no global order: each member's log holds only
   >    its own author's events, so honest members diverge at equal count. They are
   >    therefore excluded from the canonical log now and surfaced as local
   >    `ContextEvent`s. **ADR-051 (causal-DAG application-event ordering)** gives
   >    them a convergent canonical order — each event references the
   >    DAG heads its author had observed (validated: must-resolve + must-include-
   >    frontier), and every member linearizes the same DAG identically — at which
   >    point they re-enter the canonical log as convergent leaves. Until ADR-051
   >    lands they are local. (The §25 KAT vectors already carry no `MessageSent` /
   >    `ToolInvoked` / `PaymentReceived` leaf, consistent with this.)
   >
   >    *Scope:* this covers the **intra-context, per-author** `ToolInvoked`
   >    emission. The **cross-context tool-call saga** (§6) records its `ToolInvoked`
   >    / `CrossContextToolInvoked` within the saga's MLS-Commit phase — commit-
   >    ordered and *convergent*, canonical by design (its `tool_invoked_event_id`
   >    is a signed `CrossContextToolReceipt` field) — and is **not** in this
   >    per-author exclusion.
   >
   > 3. **Per-committer broadcast-retry bookkeeping (permanent — kept as an
   >    `EventType`, never durably appended).** `CommitBroadcasted`,
   >    `CommitBroadcastPending`, `CommitBroadcastSucceeded`, and
   >    `CommitBroadcastFailed` track one member's *own* attempt to push an
   >    MLS-Commit it authored onto the transport (and its persistent-retry queue,
   >    PR #1606 C6). Only the **broadcasting committer** has any notion of these
   >    events — a receiver that processes the resulting commit holds no record of
   >    the sender's transport retries — so a committer appends them while
   >    receivers append nothing, and the two diverge at equal `event_count`: the
   >    exact §9.9.3 false-positive equivocation this exclusion removes. Unlike the
   >    category-2 per-author application activity, these have **no convergent order
   >    even under ADR-051** (a transport-send outcome is not a causal-DAG
   >    application event; it has no cross-member referent to linearize), so they
   >    are excluded **permanently**, not interim. They remain in the closed
   >    `EventType` set (the 77-variant set is not narrowed) but are NEVER passed to
   >    `append_context_event`; the three retry-sweep lifecycle states
   >    (`CommitBroadcastSucceeded` / `CommitBroadcastPending` /
   >    `CommitBroadcastFailed`) and the enqueue-time `CommitBroadcastPending` are
   >    surfaced as local `ContextEvent`s (`CommitBroadcasted` first-attempt success
   >    is not surfaced at all — a successful send is the unremarkable default). No
   >    durable consumer (checkpoint, export, or proof) reads them.
   >
   > **Consequence emission (auto-derived, never consensus).** The `Consequence*`
   > variants remain in the taxonomy, but a consequence leaf is emitted by
   > **deterministic auto-derivation from the convergent log**: every honest
   > member, processing the same convergent event, evaluates the same rules over
   > the same convergent state and appends the identical consequence leaf at the
   > identical position — no per-receiver evaluation, no local receive-buffer or
   > estimated-timestamp input, no proposer or vote. This preserves §7.3.7's
   > "automatic, not governance-discretion" property *and* §9.9.3 convergence. By
   > the convergence rule above, convergent-triggered rules (governance
   > warning-counts, role / lifecycle) are durable and convergent now;
   > **velocity / rate-triggered rules are NOT convergent records.** A *rate*
   > (count ÷ time) would need a convergent clock, which the protocol neither has
   > (no operator / transport-independent / offline ⇒ no trustless wall clock) nor
   > needs. Rate-limiting is **local flow control** — each member throttles its own
   > intake on its own clock (the live spam defense, §23.16.8) — not a recorded
   > consequence. A durable **suspension** is a **governance consequence** (ADR-031)
   > whose commit *is* both its execution and its record: there is no split between
   > executing a consequence and recording it (that split was a phantom — flow
   > control isn't a record, and a suspension's execution and record are one commit).
   > A member observing sustained local throttling auto-proposes the suspension; it
   > commits per the context's *declared* governance model (mechanical, not an ad-hoc
   > vote — §7.3.7's "automatic, not governance-discretion" preserved). See ADR-051 §6.
   >
   > **Other derived per-author facts.** `tool_invocation_count` (§7.3.2) is a
   > convergent *count* over the causal DAG (ADR-051) — no clock; interim-local
   > (`anchored=false`) until that DAG lands. Economic `SenderVelocity` /
   > `ContextMessageRate` pricing (§19.7) is enforced at `authorize()` by the payer's
   > own SDK against a local spending ledger — local and self-metered, no convergent
   > clock. Neither needs (nor gets) a convergent velocity clock.
   >
   > **Local-only `ContextEvent` notifications** that never reach the Merkle log
   > (e.g. `MessageReceived`, `EquivocationDetected`, `PseudonymAnnounced`,
   > `DegradedMode`, `BufferOverflow`, `SequenceGapDetected`, `WelcomeGenerated`,
   > `CheckpointCosignatureRequired`) are receive-buffer signals, not log entries,
   > and so are out of `EventType`'s scope entirely.
   >
   > **Name-string defects corrected by this amendment.** Several runtime call
   > sites passed parameters baked into the event *name* — either as `format!`
   > strings (`"ContextTombstoned:{dest}:{pid}"`, `"ContextMigrationCancelled:{pid}"`,
   > `"AppBound:{did}:{name}:{ver}:[{caps}]"`, `"AppUnbound:{did}"`) or as an
   > entire JSON blob used as the type tag (`{"event":"SpendApproved",…}`,
   > `{"event":"TtlExtended",…}`, `{"event":"TtlExtensionRejected",…}`). Each is a
   > defect: it makes the signed leaf preimage non-convergent and un-enumerable.
   > The correct end state is the typed variant with all parameters in
   > `EventPayload`, as the variant comments above specify. (The canonical
   > variant casing is `TtlExtended`/`TtlExtensionRejected`; spec prose elsewhere
   > writes `TTLExtended`/`TTLExtensionRejected` — the `EventType` variant spelling
   > is authoritative.)

   **Rejected alternative — typed catch-all (`EventType::Other(String)`).**
   Rejected because it reintroduces free-form strings into the signed preimage
   (the non-convergence vector being removed), violates the closed/complete-set
   and No-DOA principles, and defeats compile-time cross-bridge tag parity. The
   closed set is achievable because every Merkle-logged event is enumerable from
   a finite, governing source: governance actions (ADR-031 §3 `GovernanceAction`),
   lifecycle/migration transitions (ADR-049 §9 / §5.11A), membership and access
   changes (§5), media sessions (ADR-024), economic actions (§19),
   consequence-enforcement outcomes (phase-4 trust engine / §7.3.7), app-sandbox
   binding (§8), compromise recovery (§9.12 step 2 MLS group-epoch advance), and
   provenance (§7.3). Lifecycle, consequence, recovery, and app-sandbox
   events are enumerable yet are **not** `GovernanceAction`s — the closure
   argument rests on the union of all these sources, not on
   `GovernanceAction::variant_name()` alone. Enum expansion is strictly superior.

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

   > **Superseded by ADR-052 (Unified Construction Pattern).** The fluent typestate builder (`.domain()/.identity()/.storage()/.build()`) mandated here is replaced by a flat `NodeConfig` config object constructed via `Node::start(config)` / `Node::start_for_testing(config)`. Only this AC is superseded; the rest of ADR-032 stands. See ADR-052 for the rationale and the full pattern.

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

WebTransport is the browser-facing equivalent of QUIC. The browser client transport uses the browser's `WebTransport` API over HTTP/3. Server-side, relay handles both QUIC and WebTransport sessions — they're both QUIC underneath.

Fallback chain: WebTransport → WebSocket → error. The browser client transport attempts WebTransport first, falls back to WebSocket when the `WebTransport` API is unavailable or connection fails.

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
| `crates/scp-transport/src/webtransport/client.rs` | Client-side WebTransport adapter (browser client transport) |
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

- **Magic byte prefix for version detection.** ASCII `"SCP"` + `version_u8` prefix on the decrypted inner payload. After AES-256-GCM decryption, check first 3 bytes for `BROADCAST_CONTENT_MAGIC`. If matched, read 4th byte as version and deserialize remaining bytes as MessagePack `BroadcastContent`. Legacy payloads (no magic prefix) are treated as raw bytes. False-positive probability is approximately 1/2^24 for uniformly random legacy payloads. Since this is a pre-launch breaking change, all existing broadcast content should be re-published under the new format.
- **Typed `AssetEntry` for SDK publish.** `AssetEntry { path: ContentPath, content_type: MimeType, body: Vec<u8> }` — typed parameter prevents positional transposition. `broadcastPublishAsset` (single) and `broadcastPublishAssets` (batch + commit) across all FFI bridges.
- **Deploy manifest blob for persistence.** A special broadcast message containing the complete `path -> blob_id` mapping for a deploy. Loaded on `enable_broadcast_projection()` to rebuild path index on node restart. Solves persistence, recovery, and dedup in one mechanism.
- **`ArcSwap` per-context for lock-free concurrent reads.** `Arc<ArcSwap<PathIndex>>` per `ProjectedContext` — NOT on the shared `projected_contexts` registry lock. HTTP handlers read the current deploy via `ArcSwap::load()`. Index is built at commit time only (not during per-asset publish). Per-asset publish requires no write locks on the registry.
- **Node-local `SiteConfig`.** Site configuration (hostname, index path, resource limits, CSP override) is passed to `enable_broadcast_projection()`. NOT part of governance-governed `ProjectionPolicy` — deployment concerns stay out of governance.
- **Required security headers.** All site responses include `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, `Referrer-Policy: same-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`. Each projected context MUST have its own hostname/subdomain for origin isolation.
- **Cache behavior via `immutable` flag.** `ContentMetadata.immutable: true` assets get immutable 1-year cache. `immutable: false` (default) assets get `max-age=0, must-revalidate` with ETag for CDN revalidation. 404 responses get `Cache-Control: no-store`. No heuristic content-hash detection.

### Rationale

- **Structured inner payload:** The relay stays dumb — content structure is a post-decryption concern. Putting metadata in the outer `BroadcastEnvelope` would violate the relay capability ceiling (§9.9.1).
- **Magic byte prefix over heuristic detection:** MessagePack markers have a ~10% collision rate on arbitrary payloads and create a parsing oracle. A 3-byte ASCII prefix ("SCP") has approximately 1/2^24 false-positive probability for uniformly random legacy payloads. Since this is a pre-launch breaking change, all existing content should be re-published.
- **Deploy manifest blob:** Solves persistence, recovery, and dedup in one mechanism. Without it, the path index is lost on node restart and must be reconstructed by scanning all blobs — expensive and fragile.
- **`ArcSwap` per-context:** Eliminates registry lock contention during batch publish. HTTP read handlers are completely lock-free; publish operations only touch per-context state.
- **Node-local `SiteConfig`:** Hostname binding, index path, and resource limits are deployment concerns that vary per node. Including them in governance-governed `ProjectionPolicy` would require governance actions to change a DNS mapping — inappropriate coupling.

### Rejected Alternatives

1. **Cleartext metadata on `BroadcastEnvelope`.** Would expose content paths and MIME types to relays, violating the relay capability ceiling (§9.9.1). Relays must not learn content structure.
2. **Heuristic version detection via MessagePack markers.** First-byte heuristics on MessagePack payloads have a ~10% collision rate and create a parsing oracle (attacker-controlled payloads could trigger version misparsing). Magic byte prefix is unambiguous.
3. **In-memory-only path index without manifest.** Path index is lost on node restart. Reconstructing from a blob scan is expensive (enumerate all blobs, decrypt each, extract metadata) and fragile (relies on blob TTL not having expired). The manifest blob makes restart recovery O(1).
4. **SPA fallback.** Excluded — introduces security edge cases (CDN 404 caching, information disclosure profile change) and is a deployment convenience, not a protocol concern. Reverse proxies handle this transparently.
5. **`ContentEncoding` enum.** Excluded — pre-compressed content delivery introduces complexity (gzip bomb validation, encoding trust) without proportional value. tower-http handles compression on the fly.
6. **Staged deploy API with typestate.** A `DeployBuilder` with typestate transitions (`Publishing` → `Committing` → `Live`) adds API complexity without safety benefit — the batch publish pattern (publish all assets, then commit) is simpler and already atomic at the commit boundary.

### Dependencies

- **ADR-035 (Local HTTP Control API and Broadcast Projection):** `ProjectedContext` type, projection endpoint composition, `NodeState` extensions, `Arc<dyn BlobStorage>` sharing.
- **§5.14 (Broadcast Contexts):** `BroadcastEnvelope`, `BroadcastKey`, `BroadcastAdmission`, per-author AES-256 keys, `routing_id` derivation.
- **§18.11 (HTTP Broadcast Projection):** Feed endpoint, per-message endpoint, decryption architecture, security properties, SDK surface.

### Acceptance Criteria

1. **`BroadcastContent` struct** with `version: u8`, `metadata: ContentMetadata`, `body: Vec<u8>`. Wire format: `BROADCAST_CONTENT_MAGIC ++ version_u8 ++ MessagePack(BroadcastContent)`.
2. **`ContentMetadata` struct** with `path: Option<ContentPath>`, `content_type: Option<MimeType>`, `deploy_id: Option<String>`, `etag: Option<String>`, `immutable: bool` (default `false`). Cache behavior is determined by the `immutable` flag, not by heuristic content-hash detection.
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
13. **`broadcastPublishAsset` and `broadcastPublishAssets`** SDK methods across all FFI bridges. Typed `AssetEntry` parameter (`{ path: ContentPath, content_type: MimeType, body: Vec<u8> }`). Returns `{ blobId, etag }`. Content-hash dedup.
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
| `bindings/typescript/src/context.ts` | `broadcastPublishAsset`, `broadcastPublishAssets` |
| `bindings/python/scp_sdk/context.py` | `broadcast_publish_asset`, `broadcast_publish_assets` |

**Estimated functions:** ~20-25 public functions, ~15-20 internal helpers across all files.

---

## ADR-052: Unified Construction Pattern

> **Note:** ADR-052 is numbered non-sequentially (same convention as ADR-032/035/042). It lives in the Phase 2 document because its primary worked example is `ApplicationNode` construction (ADR-032, `scp-node`), but its scope is cross-cutting: it governs every developer-facing construction entry point across all five language SDKs.

**Status:** Decided

### Context

SCP's thesis is the agentic Internet, and a direct corollary governs the SDK: **its primary author is an LLM**, writing across five languages (Rust core + Python, TypeScript, Swift, Kotlin). "Best for the model writing against it" — first-pass authorability with no compile-retry loop — is therefore *the* design criterion for the construction surface, not idiomatic-Rust-for-its-own-sake. This is now ratified as the **Agent-first API design** builder tenet in CLAUDE.md; this ADR is its first worked example, and `.docs/standards/construction.md` is its enforced enactment.

Today the construction surface is **three different patterns**:

1. **Typestate builder** — `ApplicationNodeBuilder` (`crates/scp-node/src/lib.rs`): generic markers `<K, D, S, Dom, Id>`, `HasDomain`/`HasNoDomain`/`HasIdentity` `PhantomData` states, ~25 `.with_*` methods, and a `build()`/`build_for_testing()` split. This is the LLM-hostile outlier: phantom required-ordering the model loses track of (→ compile-retry loops), required steps invisible because they are encoded in types rather than fields, and a shape that does not translate to four of five languages (Python, TypeScript, Swift, Kotlin have no typestate).
2. **Flat config objects** — `RelayConfig` (`crates/scp-transport/src/native/server.rs`), `HostSiteOptions` (`crates/scp-node/src/self_host.rs`), and the cross-FFI `StorageConfig` enum. Already the target shape, already mapped identically across all three bridges.
3. **Options-objects in SDK wrappers** — Context and Identity already use them in Python/TypeScript/Swift, while Rust uses a fluent builder (the `sdk-common.md` Context-creation divergence). The same operation has two different shapes depending on language.

ADR-032 §AC-6 mandated the typestate builder. Eliminating it follows directly from the Agent-first API design tenet (CLAUDE.md): typestate the LLM author cannot track is a defect, not a safety feature.

### Decision

Adopt **one flat-config-object construction pattern** for every developer-facing construction entry point — Node, Relay, `host_site`, Context, Identity — **identical in all five languages**, optimized for first-pass LLM authorability. Each entry point is **one flat config object** plus a single entry function, named by the entry-verb rule (construction.md): `Thing::start(config)` for entry points that **spawn a running server/runtime** (`Node::start`, `Relay::start`), `Thing::create(config)` for **value/handle construction** (`Identity::create`, `Context::create`).

This supersedes **only ADR-032 §AC-6** (the `.domain()/.identity()/.storage()/.build()` builder mandate). Every other acceptance criterion and decision in ADR-032 stands unchanged.

The pattern and its five mechanical rules (M1–M5) are specified in full in `.docs/standards/construction.md`. In summary:

- **M1** — enums, not booleans, for semantic choices (`Reach`, `BridgeRole`, `TlsMode`, `DhtMode`).
- **M2** — the security-critical choice is required or fail-safe-defaulted, never silently unsafe (DHT address publication defaults to no-publish; publishing requires an explicit production-tier selection). This DHT-publish rule applies to **both** `NodeConfig` and `SiteConfig` — each carries a `dht: DhtMode`, so M2 fires for Site TLS *and* Site DHT, not TLS alone. M2 covers all five entry points: Relay's security-critical choice is `BridgeRole`, which defaults to the fail-safe `Disabled` (an `Enabled` bridge is reached only by explicit opt-in, never by omission); Identity's is persist-or-not (`persistence: None` is the ephemeral fail-safe default); Context's is the required `ContextCreation` enum (no default).
- **M3** — required capabilities fail loud, never silent no-op (modelled on `StorageConfig` fail-closed).
- **M4** — no whole-struct `Default` when any field is security-relevant or irreducible; required fields are non-`Option`, with a `Thing::defaults(required…)` factory for the spread idiom.
- **M5** — one greppable contract: exactly one real constructor per type; no `*Builder`, no typestate markers, no positional construction. The `EncryptedStorage` `start`/`start_for_testing` trait-bound split is the single allowed exception.

The two guarantees the typestate markers previously enforced collapse into **required enum fields** — still compile-checked, but LLM-legible:

- `Reach` (the addressing XOR, one required field): `Domain { domain }` | `NatTraversal` | `Tunnel { public_url }` | `Local`.
- `IdentitySource` (required): `Generate { custody, did_method }` | `Persisted { custody, did_method }` | `Explicit { identity, document }`.

### Rationale

- **Cites the Agent-first API design tenet (CLAUDE.md).** Typestate is unsafe *for the actual author* — a model that cannot track phantom ordering enters a compile-retry loop. Encoding required choices as required fields makes the same compile-time guarantee legible.
- **"No DOA decisions" (CLAUDE.md).** Three divergent construction patterns is a design that needs replacing; replacing it now, with one pattern that holds across all five languages, is the permanent commitment.
- **"APIs: self-evident, one happy path" (CLAUDE.md).** One config object, one entry function, one shape per operation across all bindings — the maximally self-evident surface.
- **Injection-through-initializers is preserved (architecture.md §2.5).** Custody, storage, DID method, and transport remain trait-injected; they are carried as typed fields/selectors *inside* the config object. Nothing is constructed by a module that should receive it. The flat config object is the initializer the §2.5 invariant already requires — it is the vehicle for injection, not a bypass of it.
- **Proven cross-language mapping.** The existing `StorageConfig` FFI mapping already demonstrates the equivalence (see the canonical table in construction.md §Five-language equivalence). The pattern is not speculative.

### Rejected Alternatives

1. **Keep the typestate builder kernel (status quo).** Rejected. The typestate markers are the precise mechanism that produces compile-retry loops for an LLM author and the shape that does not translate to four of five languages. "Compile-time safety" is real but is fully recovered by required enum fields, which are also legible. Retaining the builder would entrench the worst case against the Agent-first tenet.
2. **Box the injected providers as `dyn` (e.g. `Arc<dyn Storage>`) to flatten the generics away.** Impossible, not merely undesirable: `KeyCustody`, `Storage`, and `DidMethod` use return-position `impl Trait` in trait (RPITIT) and are **not object-safe** — `Arc<dyn Storage>` does not compile, and the codebase already works around this in several places. Boxing would also put `async-trait` allocation on storage-read and sign hot paths, regressing the ADR-049 lock-free-read invariant. Providers therefore stay **typed enum-selectors / concrete types**, never `dyn`. The config object carries the generics on its selectors; they are not erased.
3. **Demote the `EncryptedStorage` seal to a runtime check** so production and testing share one unconditional `start(config)`. Rejected — this weakens the compile-time encryption-at-rest guarantee (`EncryptedStorage` is a sealed trait; production `Node::start` requires `S: EncryptedStorage`, the `start_for_testing` path is feature-gated). Production must not be able to persist plaintext, and that must hold at compile time, not by convention. The guarantee is preserved as the `start`/`start_for_testing` trait-bound split — the one allowed exception to M5 — and additionally backed by a structural test that the unencrypted path is unreachable from the production constructor.

### Acceptance Criteria

1. **`.docs/standards/construction.md`** exists, frames itself as the enactment of the Agent-first API design tenet, and specifies rules M1–M5, the per-entry-point target shapes, and the five-language equivalence table.
2. **CLAUDE.md** carries the **Agent-first API design** builder tenet, and the "APIs: self-evident, one happy path" architecture rule references it.
3. **`NodeConfig`** replaces `ApplicationNodeBuilder`: required fields `reach: Reach`, `identity: IdentitySource`, and a required storage slot (no whole-struct `Default`); enum fields `tls`, `dht`; defaulted optionals for the remainder. The Rust-core `NodeConfig` stays generic over the storage type `S` (the `<K, D, S>` generics survive, carried by the config and its selectors) and carries the injected provider as a typed core slot — it does **not** carry the FFI `StorageConfig` enum (scp-core does not depend on scp-ffi). Each FFI bridge mirrors `NodeConfig` as its own per-bridge config, lowering the storage slot to that bridge's `StorageConfig` enum. Entry: `Node::start(NodeConfig)` (production, `where S: EncryptedStorage`) and `Node::start_for_testing(NodeConfig)` (feature-gated, any `Storage`). The `Dom`/`Id` typestate markers are deleted.
4. **`RelayConfig`** replaces `supports_bridge: bool` with a `BridgeRole` enum (`Default = Disabled`, the fail-safe). `BridgeRole::Enabled` is **payload-free**: brokering authenticates each `BRIDGE_REGISTER` by an Ed25519 signature over the DID-to-routing-ID mapping (SCP-247, §10.12.4), so enabling the broker role needs no shared secret. The relay's `bridge_secret: Option<[u8;32]>` is a **separate, orthogonal** field — the internal-relay WebSocket connection-admission secret (`Authorization: Bearer`), set independently of the broker role (a Node sets `bridge_secret` on a relay that brokers nothing) — and is therefore **not** folded into `BridgeRole` and not part of the construction-pattern surface. `RelayConfig` may keep its whole-struct `Default` under M4 precisely because `BridgeRole::default() == Disabled` makes its sole security-consequential field fail-safe. Entry: `Relay::start(RelayConfig, storage)` (the SDK-facing entry, which wraps the internal low-level `RelayServer::new(config, storage)` — `RelayServer::new` is not the public pattern surface; see the entry-verb rule in construction.md).
5. **`HostSiteConfig`** folds `HostSiteOptions`: `reach: Reach` (required), `tls: TlsMode` (the same enum as `NodeConfig.tls`; folds the `plaintext` bool), `dht: DhtMode`, plus deployment fields. The host config takes the name `HostSiteConfig`, **not** the bare `SiteConfig`, because `crates/scp-node/src/projection.rs` already exports an FFI-surfaced `SiteConfig` (virtual-host deploy limits) that the three bridges and the SDK capability matrix track — renaming it is an out-of-scope bridge-parity hazard, so the construction host config takes the distinct name (a compiler-level constraint, the one legitimate naming deviation). `host_site` (today `host_site(opts: HostSiteOptions)`) remains the fail-safe sugar tier, constructing a full `HostSiteConfig` and delegating. `Reach` is a new enum (built in P1) that folds the existing `PublicSurface`, `ReachabilityTier`, and `skip_nat`/`no_domain` machinery in `crates/scp-node/src`; `DhtMode` (currently in `crates/scp-node/src/self_host.rs`) is promoted to a shared location so Node and Site share one definition.
6. **`ContextConfig { creation: ContextCreation }`** with `<manager>.create(ContextConfig)` replaces the Rust `create_context().template().build()` builder, where `ContextCreation = Template { template, peer } | Explicit { ceiling, roles, governance, memory_scope }`. This eliminates the `sdk-common.md` Rust/options-object divergence — all five languages now use the same options-object shape. **Receiver:** the verb is `create`, but unlike `Identity::create` (a manager-free top-level constructor) a context is created **within an existing manager runtime** — the Rust-core `Supervisor` (which absorbed the former `ContextManager`, ADR-049) that owns the MLS group creation, actor spawn, and event-log init a context create performs, and that the FFI bridges already drive via `create_context`. The entry is therefore the verb-`create` method on the live manager (`<manager>.create(ContextConfig)`), surfaced by the language SDKs as a method on their SDK handle (`sdk.create_context` / `sdk.createContext`); see the Context receiver carve-out in construction.md. **Bilateral peer:** `Template`'s optional `peer` is for the invitation step; invitation/Welcome-delivery is a higher SDK layer, so until it is wired the core `create` entry rejects a supplied `peer` with a loud typed `ContextCreationError::BilateralPeerNotSupported` rather than silently dropping it (CLAUDE.md "no silent" tenet). `peer: None` is the supported form at this layer.
7. **`IdentityConfig { method, custody, persistence }`** with `Identity::create(IdentityConfig)`; `method` and `custody` required. `persistence: None` is the fail-safe default (ephemeral identity, no key material at rest); when `Some(StorageSlot)`, the production `Identity::create` path binds the slot to `EncryptedStorage` exactly as `Node::start` does — identity key material persists only to an encrypted slot, including via `StorageSlot::Custom` (the `Custom(concrete)` it carries must be an `EncryptedStorage` type). A Node's persisted identity is the same model sourced differently: it reuses the Node's own `NodeConfig.storage` slot rather than a separate identity slot.
8. **Five-language equivalence:** each config object and its enums map identically across Rust, Python, TypeScript, Swift, and Kotlin, per the canonical five-language equivalence table in `.docs/standards/construction.md` (the existing per-bridge `StorageConfig` mirror is the worked precedent). The Rust-core-only `Custom(concrete)` advanced-injection variant and its FFI-named/`parse_custody` asymmetry are likewise stated canonically in construction.md (§Five-language equivalence) — a Rust trait object cannot cross the FFI boundary, so the bridge mirror enums omit it. This Rust-core-only/FFI-named split is correct, not a coverage gap.
9. **Enforcement (additive):** a structural check (`scripts/check-construction-pattern.py`) bans `*Builder` types and typestate markers in construction modules and bans bools where M1 requires enums; the `EncryptedStorage` structural test proves the unencrypted-storage path is unreachable from the production identity-persisting constructors (`Node::start` and `Identity::create`). Three clauses are **not** mechanically checkable and are enforced by human review: (a) whether a surviving `bool` is "genuinely binary state with no behavioral fork" (the M1 carve-out), (b) whether a named `Template` resolves only to fail-safe parameters (a property of template data, not config shape — M2 Context), and (c) whether each entry point's M2 default *direction* points at the fail-safe value (per entry point: Node/Site DHT no-publish, Relay `BridgeRole::Disabled`, Identity ephemeral `persistence: None`) — the check sees a default exists but cannot judge whether it is the safe one. The structural check guards config *shape*; these three are out of its reach by construction.

### Dependencies

- **ADR-032 (Addressability and Deployment):** supersedes §AC-6 only; consumes `ApplicationNode`, `RelayServer`, `host_site`.
- **ADR-035 / ADR-042 (`SiteConfig`):** the new construction host config (`HostSiteConfig`) is a **distinct** type from the existing node-local `SiteConfig` (projection deploy limits) these ADRs define — `HostSiteConfig` is the deployment-driver folded from `HostSiteOptions`, and it threads a `projection::SiteConfig` through to `enable_broadcast_projection()` unchanged; the existing `SiteConfig` is neither renamed nor reshaped.
- **ADR-048 (per-SDK idiom):** the FFI Rust layer keeps pure helpers as free functions; this ADR governs *construction entry points*, which are first-class objects in every SDK — consistent with ADR-048 §1/§7.
- **ADR-049 (lock-free-read invariant):** providers stay enum-selectors / concrete types, never boxed `dyn`, to keep allocation off the read/sign hot paths.
- **architecture.md §2.5 (injection-through-initializers):** preserved; the config object is the initializer through which injection happens.
- **Name reconciliation (`IdentitySource`):** `crates/scp-node/src/lib.rs` already defines a *private* `enum IdentitySource<K, D>` (variants `Generate { key_custody, did_method }`, `Explicit(Box<ExplicitIdentity>)`) used by the existing typestate builder. The public `IdentitySource` this ADR introduces has different variants (adds `Persisted`, field names `custody`/`did_method`). Phase B-P1 reconciles the collision — extend/reuse the existing enum or rename one — before the public type ships. The final name is an implementation decision, not fixed here.

## ADR-053: Node Is Infrastructure; Participation Is an SDK Client

> **Note:** ADR-053 is numbered sequentially after ADR-052 but, like ADR-032/035/042/052, lives in the Phase 2 document by *subject*, not by number: it governs `scp-node` (Phase 2, Context + Transport) and the self-host binary the SHB PRD ships. Its scope is cross-cutting — it constrains every construction site where a participant is created relative to a node.

**Status:** Decided

### Context

A `scp-node` (`crates/scp-node`) is pure infrastructure: a relay (store-and-forward of opaque encrypted blobs, §10.4), an identity service (DID resolution / DHT publication), and an HTTP projection surface (§10.12.11). The specs already imply that a node never *participates* in a context as itself:

- **§10.2 (Device-as-Node):** the device *is* a node, but the protocol's guarantee is "no server *owns* you" — identity and context state live with the DID, not the node.
- **§10.4 (Relay Architecture):** relays are protocol-unaware — they "store and forward encrypted blobs," and "cannot read content, inspect membership, or understand context semantics."
- **§10.5 (SDK Transport Architecture):** "The SCP SDK owns all protocol logic — contexts, agents, trust, capabilities, governance." Transport (the node's job) "is not the product."
- **§10.12.6 (Transport Security):** the relay authenticates nothing at the transport level; MLS is the confidentiality boundary; the relay is a dumb pipe by construction.

All *participation* — joining a context, creating an MLS group, publishing `BroadcastContent`, signing governance votes — is performed by an **SDK participant client** (a `Supervisor`/`ContextManager`, ADR-049) **bound to a DID**, which brings its own custody and runs the full protocol pipeline. There is exactly **one participant engine** in the codebase (the `Supervisor`); a node is never a second, special kind of participant.

"Self-host website publishing" (the SHB PRD) reads at first glance like "the node participates." It is not. It is a **co-located SDK participant client running inside the node process**, sharing the node's custody, publishing the site as `BroadcastContent` over the node's own loopback relay (§10.12.11, ADR-042). The participant and the node are distinct roles that happen to share a process.

The current implementation **violates** this boundary. `crates/scp-node/src/self_host.rs` hand-rolls the in-process `Supervisor` with a **stubbed `KeyResolver`** (`Arc::new(|_, _| None)`). A `|_, _| None` resolver means the co-located participant cannot verify any governance vote signature against a voter's document-derived key — it is a participant with verification disabled. The stub's own comment attributes this to a crate cycle (the production resolver, `document_vm_key_resolver`, lives in `scp-ffi-common`, which depends on `scp-node`). The FFI bridge, by contrast, wires the **real** resolver. The boundary this ADR draws makes the stub a recognized defect, not an accepted shape: a co-located participant is a *real* participant and MUST be constructed with the real, document-derived resolver.

### Decision

**A node is pure infrastructure and NEVER participates in a context as itself.** A node is: a relay (§10.4), an identity service, and an HTTP projection surface (§10.12.11). It holds custody and resolves DIDs, but it does not join contexts, create MLS groups, or sign protocol messages in its own right.

**All participation is performed by an SDK participant client (a `Supervisor`/`ContextManager`) bound to a DID.** There is one participant engine. A participant brings custody, a DID, and the full protocol pipeline — including the **real, document-derived `KeyResolver`** that extracts a voter's verification-method key from their resolved DID document, keyed by the requested `SigningKeyId`. A participant constructed with a `|_, _| None` resolver is incomplete by the completeness baseline (CLAUDE.md) and is forbidden.

There are **two deployment shapes** for a participant relative to a node:

- **BUNDLED (co-located).** The participant client runs **inside the node process**. Custody/keys never cross a process boundary; it is a single binary. The participant reaches the node's relay over the in-process loopback socket (`ws://127.0.0.1:<relay_port>/scp/v1`, `RelayUrlSource::DhtResolved`), authenticating with the node's bridge bearer token. **This is the self-host website binary** (`scp-node --self-host`): the co-located `Supervisor` in `self_host.rs` publishes `BroadcastContent`; the node projects it over HTTP. The participant is not the node — it is a participant that the node hosts.

- **EXTERNAL (separate process).** The participant client runs in **its own process**, connecting to a node's relay over the socket — loopback when same-box, `wss://` when off-host (§10.12.5/§10.12.6 transport rules apply). It **brings its own custody**. Its access to context content is enforced **cryptographically** (MLS group membership + UCAN capabilities — encryption-as-access-control), exactly as for any participant; the relay remains a protocol-unaware dumb pipe. External participants reach `/scp/v1` over the node's existing TLS-terminated **Full** public surface — there is no dedicated listener mode, admission token, or pre-shared secret. Relays are anonymous, DHT-auto-discovered dumb pipes that participants do not hand-pick, so reachability is governed entirely by the public-surface selection (§10.12.11), the bind address, and the TLS mode (§10.12.6), exactly as for any client of the relay. Abuse prevention for an open `wss://` relay (a spam/DoS/storage-abuse vector) is the relay's **existing** rate limiting and abuse controls (§10.4) together with relay economics (§19.8), which satisfy §10.4's "rate limiting and abuse prevention" requirement without an allowlist that is at odds with the anonymous-relay model.

The relay's `/scp/v1` route is served on the node's existing TLS-terminated **Full** public surface for EXTERNAL participants — not a separate listener mode or gated surface — while the node's dev/control and bridge endpoints remain loopback-only. Opening the relay to external participants does NOT open dev/bridge endpoints.

### Rationale

- **Makes an implied boundary explicit and mechanically enforceable.** §10.2/§10.4/§10.5/§10.12.6 already imply "node ≠ participant"; without a named decision, `self_host.rs` drifted into hand-rolling a half-participant inside the node. Naming the boundary turns the `|_, _| None` resolver from "an accepted node affordance" into a recognized defect.
- **One participant engine (CLAUDE.md "Simple over complex," "one canonical pattern").** A "node-as-participant special mode" would be a second engine with its own (degraded) construction. Co-locating the *existing* `Supervisor` instead means the bundled binary runs the **same** code path as every other participant.
- **Custody never crosses a process boundary in the BUNDLED shape** — the single-binary security property the self-host thesis depends on (§10.2 "no server owns you").
- **Keeps the relay a dumb pipe in the EXTERNAL shape.** Access control stays cryptographic (MLS/UCAN); abuse prevention is the relay's **existing** rate limiting (§10.4) and economics (§19.8), not a relay-issued credential — so external participants are served without contradicting §10.4 (protocol-unaware relay) or the encryption-as-access-control tenet.

### Rejected Alternatives

1. **Node-as-participant special mode (rejected).** Let the node itself join contexts and publish, with a node-specific participant path that may run with a reduced resolver (the de-facto status quo at `self_host.rs`). **Rejected:** it creates a *second* participant engine alongside the `Supervisor`, violating "one canonical pattern" (Agent-first API design) and "Simple over complex." Worse, the node-specific path is where the `|_, _| None` resolver hid — a node "participating" with vote-verification disabled is exactly the resolver gap this ADR closes. A node has no DID-bound participant identity of its own; making it pretend to be one blurs §10.4's "protocol-unaware relay" guarantee. Participation must always be a real `Supervisor` bound to a DID with the real resolver, whether co-located or external.
2. **Share an `Arc<dyn BlobStore>` directly between the co-located participant and the node (rejected).** Skip the loopback relay; hand the participant the node's blob backend in-process. **Rejected:** it makes the BUNDLED shape structurally different from the EXTERNAL shape (which must go over a socket), so the bundled binary would not exercise the real publish→relay→`commit_deploy` path. SHB-002 deliberately communicates via the loopback relay, "NOT a directly-shared `Arc` blob backend," so the same code path is proven end to end.
3. **Keep the stubbed `KeyResolver` as a documented node limitation (rejected).** Accept `|_, _| None` because the cycle is inconvenient. **Rejected:** violates the completeness baseline ("never `None` when data exists elsewhere in the system"; CLAUDE.md). The real value exists; the only obstacle is crate layering. That is fixed by **hoisting the pure document-VM key extraction** (`verifying_key_from_document(document, kid)`) into a lower-layer crate (`scp-identity`, which already owns `DualLayerResolver` and every extraction primitive) and having both the FFI bridges and `scp-node` consume that one shared, tested helper — not by accepting a degraded participant, and not by duplicating the extraction inline in `scp-node` (a second copy is exactly the "resolver silently ignores the `SigningKeyId`" failure mode).
4. **A relay admission token (rejected).** Add an optional relay-issued "admission token" on the external client connection to gate who may connect — whether as the access-control boundary or merely as abuse prevention. **Rejected on both counts.** As an access-control boundary it would re-introduce transport-level access control over a relay the protocol mandates be a dumb pipe (§10.4), duplicating — in weaker, relay-trusting form — the access control MLS/UCAN already enforce cryptographically (encryption-as-access-control). As mere abuse prevention it is redundant with the relay's existing rate limiting (§10.4) and economics (§19.8), and an allowlist of pre-shared secrets is fundamentally at odds with the anonymous, DHT-auto-discovered relay model (§10.4) — participants do not hand-pick relays or arrange secrets with them. External reachability is therefore governed solely by the existing public-surface, bind-address, and TLS controls; no relay-issued credential is introduced.

### Dependencies

- **Spec §10.17 (Node vs. Participant):** the normative prose this ADR enacts. (Cross-references: §10.2, §10.4, §10.5, §10.12.6, §10.12.11.)
- **ADR-049 (actor-per-context / `Supervisor`):** the one participant engine. The co-located and external clients are both `Supervisor` instances.
- **ADR-042 (Broadcast Content Delivery):** the publish path the BUNDLED participant drives.
- **ADR-052 (Unified Construction Pattern):** the participant and node are both constructed via flat config; a node config never carries "participate as self" — participation is always a separate `Supervisor` construction.

## ADR-057: Structured Capability/Trust Validation Across the FFI; SDKs Consume Typed Results, Not Prose

> **Note:** ADR-057 is numbered sequentially after ADR-056 but, like ADR-032/035/042/052/053, lives in the Phase 2 document by *subject*, not by number: it governs the capability/trust-validation surface (§7.2, Phase 2 — Context + Transport) as it crosses the FFI bridges into the language SDKs. Its scope is cross-cutting — it constrains every bridge that returns a validation outcome and every SDK that consumes one.

**Status:** Decided

### Context

UCAN capability validation has two distinct consumers with two distinct needs (§7.2.1):

- An **enforcement gate** that must fail closed at a token-presentation boundary (cross-context tool invocation, broadcast admission, role assignment). This is `validate_ucan` (`crates/scp-protocol/src/crypto/ucan/validate.rs`): the 11-step Tier-1 pipeline that returns `Ok(())` or a specific `UcanError`, and — critically — **records the nonce** (step 9, `NonceTracker::check_and_record`) as a side effect, consuming it for replay defense.
- A **diagnostic** that must report *which* checks passed without enforcing anything and without mutating state — for a trust signal an SDK surfaces to a caller deciding whether to proceed. This is `evaluate_ucan` (same file): it runs the identical sub-checks but returns a structured `CapabilityValidation` record of six per-stage booleans (`tokens_valid`, `signatures_valid`, `within_ceiling`, `nonce_valid`, `not_revoked`, `time_bounds_valid`), never throws, and probes the nonce **read-only** (`NonceTracker::check_replay`, never `record`), so it is safe to call repeatedly on the same token without burning its nonce.

The Rust core plus all three FFI bridges already expose `evaluate_ucan` as the structured op `ucan_evaluate` returning `CapabilityValidation` (PyO3 `crates/scp-ffi/src/ucan.rs`; NAPI `crates/scp-ffi/napi/src/ucan.rs` + `scp.rs`; UniFFI `CapabilityValidationRecord`; the WASM bridge was removed per ADR-055 (`.docs/adrs/phase-4.md`)). The structured substrate exists at every layer below the SDK wrapper. The capability matrix (`.docs/standards/sdk-capability-matrix.json`, `UCAN.evaluate`) records this as bridge-present, SDK-wrapper-pending, with exemptions explicitly naming "the C3c SDK-parity follow-up."

What is **wrong** today is how the SDKs consume validation outcomes. A first-principles audit of the trust/capability SDK surface found the Python SDK reverse-engineering the per-check breakdown by **string-matching the human-readable error prose** the throwing gate emits — parsing strings like `[SCP-PERM-3001] permission error: …` in `trust.py` to reconstruct *which* of the six checks failed. This is an antipattern on two independent grounds:

1. **It is brittle by construction.** It couples the SDK to the exact wording of error messages — a denylist of prose spellings that grows every time the core rephrases a message, and silently mis-classifies the moment the wording drifts. The structured truth (`CapabilityValidation`) was discarded and then guessed back from a lossy projection (a flattened error string).
2. **It masked a real security defect.** Because the test mocks emitted prose without modeling nonce *state*, a multi-attestation nonce bug went undetected: the prose-reconstruction reported `nonce_valid` from a string that the mock produced unconditionally, so the suite never exercised the path where the nonce check actually consumes/observes state across multiple attestations. A typed result whose mocks must model nonce state would have surfaced it.

The structured op was built precisely to retire this antipattern. This ADR records the decision the C3c SDK rebuild rests on.

### Decision

1. **Capability/trust validation results cross the FFI as typed, structured records — never as prose to be parsed back.** The canonical structured result is `CapabilityValidation`: the six explicit per-stage booleans defined in `validate.rs`. The record has an **identical shape across every binding** (per the Agent-first API design tenet): snake_case fields in Rust and PyO3, camelCase under the NAPI serde projection, and a UniFFI `Record` (`CapabilityValidationRecord`) for Swift/Kotlin. The field *set* and *meaning* are identical everywhere; only the per-language casing differs.

2. **The throwing gate and the diagnostic are two distinct operations and stay distinct.** `ucan_validate` is the enforcement GATE: fail-closed, side-effecting (records the nonce), the only thing permitted at a token-presentation boundary. `ucan_evaluate` is the read-only DIAGNOSTIC: returns the structured `CapabilityValidation` without throwing and **without recording nonce state** (read-only `check_replay`). The diagnostic is a point-in-time snapshot, not a pre-flight guarantee that a subsequent `ucan_validate` will accept the token (the nonce may be recorded, or the token revoked, between the two calls). Neither operation is reconstructable from the other's output: a caller wanting the per-check breakdown calls `ucan_evaluate`; a caller enforcing at a boundary calls `ucan_validate`.

   2a. **The diagnostic's challenge capability is OPTIONAL; the gate's is MANDATORY.** `ucan_validate` always requires a concrete `required_capability` — enforcement at a presentation boundary is always *for* a specific invoked capability. `ucan_evaluate` makes the challenge capability optional: with **no challenge** it evaluates the token's INTRINSIC validity (signature/chain/issuer/audience/key-scope/Category-A/attenuation, all-attestation ceiling over the token's own `att`, nonce, revocation, time bounds) and SKIPS the invoked-capability grant-match entirely; with a challenge supplied it additionally requires the token grants that capability. Omitting the challenge never flips any `CapabilityValidation` field to `true` that another check would set `false` — every other stage still runs and `within_ceiling` still enforces the all-attestation ceiling — so the diagnostic stays fail-closed in both modes. The intrinsic mode is the one a trust signal uses: a participant's tokens are assessed for general validity when there is no specific capability to challenge. (Passing a bare `*` "match anything" sentinel is NOT this — the gate rejects it as a malformed capability URI; the absence of a challenge is expressed by *omitting* the capability, not by a wildcard string.)

3. **SDKs MUST consume the structured result and MUST NOT parse prose error strings to infer validation outcomes.** Reconstructing *which check failed* by matching error message text is forbidden. The per-check breakdown comes from `CapabilityValidation`; nothing else.

4. **SDK error *typing* derives from the bridge error-code taxonomy, surfaced through a single mapping chokepoint — not per-call string classification.** Where an SDK must classify a thrown error (e.g. mapping a gate rejection to a typed SDK exception), it maps on the structured `[SCP-CAT-NNNN]` error *code* the bridge attaches (where `CAT` is a placeholder for the relevant allocated category prefix — `IDENT`/`CTX`/`PERM`/`CRYPTO`/… per `scripts/check-error-codes.sh` — not a literal `CAT` prefix), at **one** mapping site, not with a try/catch ladder of `if message.contains(...)` at each call site. One chokepoint (e.g. a Proxy/wrapper that maps code → typed error) keeps the mapping closed and auditable; scattered string classification is the same brittle denylist this ADR is retiring, in a second location.

5. **Per-SDK idiom is preserved.** This decision fixes *what crosses the FFI* (a typed record) and *what SDKs must not do* (parse prose). It does NOT dictate that every SDK expose an identically-named or identically-shaped public wrapper. Each SDK exposes the structured result through its own idiomatic surface, and the wrappers land per-SDK; do not propagate one binding's wrapper shape onto another (per the per-SDK-idiom lesson, `.docs/lessons/per-sdk-idiom-not-cross-language-dogma.md`).

### Rationale

- **Eliminates phantom provenance at the SDK boundary.** Prose-parsing makes the SDK's notion of "which check failed" a *guess* about the core's behavior, decoupled from the core's actual result. Consuming the typed record makes the SDK's view exactly the core's view — the structured truth flows down unaltered (artifact-flow / CLAUDE.md "code does not inform specs").
- **Closed, not open.** A typed six-field record is closed by construction: a new failure mode either maps to an existing stage boundary or forces an explicit, reviewed change to the record. A prose denylist is open-ended — it chases "one more spelling" forever (CLAUDE.md "Guard against … non-convergent enforcement").
- **Gate vs. diagnostic separation is a security property, not ergonomics.** Folding structure into the throwing gate would either make the gate non-throwing (defeating fail-closed enforcement) or make the diagnostic side-effecting (consuming the nonce on every trust-signal probe — a nonce-burn DoS and a correctness hazard). Keeping them separate keeps each sound.
- **Mocks that must model nonce state catch nonce bugs.** Consuming the typed result forces test doubles to populate real per-stage outcomes — including nonce state — rather than emitting unconditional prose. The masked multi-attestation nonce bug is exactly the class this surfaces.

### Consequences

- **The C3c SDK rebuild** (downstream code work, governed by this ADR and §7.2.4): delete the Python prose-parser in `trust.py`; add the TypeScript public wrapper(s) over `ucanEvaluate`/the trust-signal consumer; route SDK error typing through a single mapping chokepoint keyed on `[SCP-CAT-NNNN]` codes; and rebuild the test mocks to model nonce state rather than emit prose.
- **Capability-matrix cells flip true** as each SDK's idiomatic wrapper lands: the `UCAN.evaluate` row's per-SDK `false` entries (currently exempted as "the C3c SDK-parity follow-up") are cleared SDK-by-SDK. The Python and TypeScript wrappers land in the C3c rebuild; **the Kotlin and Swift idiomatic wrappers are tracked separately** (the UniFFI bridge already exports `CapabilityValidationRecord`; only the idiomatic SDK sugar remains).
- **One narrow core change: the diagnostic's challenge capability becomes optional (Decision 2a).** `validate_ucan`/`evaluate_ucan`/`CapabilityValidation` and the three bridge exports already exist; this ADR records the consumption contract and does NOT add a new protocol operation. The only signature change is `evaluate_ucan`'s `required_capability` going from mandatory to optional (`Option`), with the corresponding bridge `ucan_evaluate` capability argument becoming optional. The enforcing gate `ucan_validate` is UNCHANGED — its `required_capability` stays mandatory. This was driven by the C3c trust-signal consumer, which has no specific capability to challenge and previously passed a `*` sentinel the real bridge rejected (see Decision 2a and §7.2.4).

### Rejected Alternatives

1. **Keep parsing prose error strings (the status quo, rejected).** Reconstruct the per-check breakdown by string-matching `[SCP-PERM-3001] …`-style messages. **Rejected:** this is the audit's root cause. It is brittle (a prose denylist that breaks on rewording), lossy (a structured truth flattened to a string and guessed back), and it actively masked a nonce bug because the mocks emitted prose without modeling state. A structured record already exists at every layer; discarding it to re-parse a string is negative value.
2. **Overload the throwing `ucan_validate` to also return structure (rejected).** Make the single gate return both an outcome and the per-stage breakdown. **Rejected:** it conflates the enforcement gate with the diagnostic. To return structure on the failure path the gate would have to stop throwing (losing fail-closed enforcement at presentation boundaries), and to produce the breakdown it would have to run all stages — including recording the nonce — turning every diagnostic probe into a nonce-consuming side effect (nonce-burn DoS). The gate must stay fail-closed and side-effecting; the diagnostic must stay non-throwing and read-only. Two operations, two contracts.
3. **Per-call try/catch classification in the SDK (rejected).** Instead of one chokepoint, classify each thrown error at each call site with a local `catch` that inspects the error. **Rejected:** it scatters the (already-rejected) string/denylist logic across every call site and re-creates the unbounded-denylist problem in N places. A single mapping chokepoint keyed on the structured `[SCP-CAT-NNNN]` code is closed and auditable; per-call classification is neither.

### Dependencies

- **Spec §7.2 (Layer 1: Protocol Enforcement), §7.2.1 (Tier 1 full UCAN validation), and §7.2.4 (Structured capability evaluation):** the normative prose this ADR enacts. §7.2.4 defines the structured-evaluation result and the gate-vs-diagnostic distinction at protocol level.
- **ADR-016 (11-step UCAN validation pipeline, `.docs/adrs/phase-3.md`):** the gate `ucan_validate` enacts; `evaluate_ucan` mirrors its stage boundaries exactly.
- **ADR-009 (Role Assignment and Capability Ceiling Enforcement):** the `NonceTracker` foundation — its acceptance criteria define the `NonceTracker` struct and the `check_and_record` (gate) / `check_replay` (diagnostic) operations whose differing nonce side effect distinguishes the gate (records) from the diagnostic (read-only probe). ADR-016 (cited above) is the normative nonce-validation pipeline (format, freshness, replay window).
- **ADR-039 (shared-DID key scope, Category-A enforcement):** sub-checks inside the `signatures_valid` stage of `CapabilityValidation`.
- **Agent-first API design tenet (CLAUDE.md) + per-SDK idiom lesson (`.docs/lessons/per-sdk-idiom-not-cross-language-dogma.md`):** identical record *shape* across bindings, but per-SDK idiomatic wrappers — not a single shape forced onto every language.
- **Lesson `.docs/lessons/sdk-consume-structured-ffi-results-not-error-prose.md`:** why prose-parsing of FFI error strings is a recurring failure mode (it masked the multi-attestation nonce defect), and the structural prevention this ADR rests on — SDKs consume the typed `CapabilityValidation`/structured result, never reconstruct per-check outcomes from message text.
- **Bridge error-code taxonomy (`[SCP-CAT-NNNN]` codes, `scripts/check-error-codes.sh`):** the source of SDK error typing, surfaced via one mapping chokepoint.

