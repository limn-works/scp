> **ARCHIVED — NOT A LIVE DECISION.** Alec cut ADR-023, Bridge Connector Protocol, on 2026-09-26 ("let's cut."), and the Track BR slice S1 pull request moved it here on 2026-10-09. Read `../HISTORY.md` before reviving any part of it. Below the rule sit two verbatim excerpts of `.docs/adrs/phase-5.md` as it stood on main when archived: lines 1–19 (the phase header, the dependency diagram and the build order), then lines 21–192 (ADR-023 from its heading through its estimate line). To restore ADR-023, paste the second excerpt back into `phase-5.md` between the `---` line that follows the build order and `## ADR-024: Real-Time Media Transport`, follow it with a blank line, a `---` line and a blank line, and restore the four header lines whose original text `../passages/from-adrs-prds-sketch.md` records.
>
> ---

# Phase 5 Architecture Decision Records — Bridges, Media, Apple Platform, Swift SDK

**Date:** February 23, 2026
**Phase goal:** Platform bridge infrastructure, real-time media transport, Apple platform, Swift SDK.
**Timeline:** Weeks 17-20
**Dependencies between ADRs:**

```
Phase 1-4 ADRs
       |
       ├── ADR-023 (Bridges) <── ADR-019 (Provenance), ADR-008 (Governance)
       ├── ADR-024 (Media) <── ADR-001 (MLS), ADR-018 (TTL/Ceiling)
       ├── ADR-025 (Apple) <── Phase 1-2 Rust + ADR-021 (UniFFI)
       └── ADR-026 (Swift) <── ADR-021 (UniFFI) + ADR-025 (Apple)
```

Build order: ADR-023 + ADR-024 (parallel, both depend on Phase 1-4) --> ADR-025 (depends on Phase 1-2 Rust + ADR-021) --> ADR-026 (depends on ADR-021 + ADR-025)

---

## ADR-023: Bridge Connector Protocol

**Status:** Decided. **Amended:** 2026-09-10 (the P-256 curve ruling).

**Amended 2026-09-10.** ADR-063, inception-derived self-certifying identity over a key-event log, left an identity one operational role, so a bridge operator holds no second key on its own identity. `09-security-model.md` §9.1 invariant 1 states the replacing model and records that its delegation anchor is unspecified, so the bridge signs under the operator's `#active` key until that anchor lands.

**Amendment (2026-09-10 — the connector signature is ECDSA on P-256).** ADR-063, inception-derived self-certifying identity over a key-event log, carries the curve ruling in §The curve and the root's custody, which names §9.5 of `09-security-model.md` as the home of its reason, and carries the provenance of the curve it superseded in §Alternatives considered. The `signature` field on this ADR's signed connector structure carries the type `P256Signature`. No other sentence of this ADR names a curve, so the ruling reaches its wire type and no decision in it.

### Context

Spec §12 comprehensively specifies bridge architecture. Bridges are protocol entities (not agents) that translate between external platforms and SCP. They have an accountable operator identity, operate in one of four modes, and create shadow identities for external platform participants. All bridged content carries full provenance chain. Shadow claiming via identity attestation enables users to transition from shadow to native SCP identity.

### Decision

Implement bridge support in `scp-core/bridge/`. Bridge connector as registered protocol entity with an accountable operator identity. The bridge operator signs bridge protocol messages with its `#active` key, because a human identity's key state names one operational role and names no agent key. Shadow identities as restricted participants (observer default). Four operating modes (Relay, Puppet, Api, Cooperative). All bridged content carries full provenance chain. Shadow claiming via identity attestation (§3.5) is one-way and irreversible.

### Rationale

- **Protocol entity over agent:** Bridges are not agents — they don't exercise judgment or make decisions. They translate between external platforms and SCP mechanically. Making them a distinct entity type prevents confusion with agents and enforces different trust evaluation (bridges are trusted to translate faithfully, not to act autonomously).
- **Accountable operator identity:** Every bridge has a human operator whose identifier is visible in context metadata. This satisfies the "human accountability" protocol tenet — bridged actions trace to the bridge operator, and through the bridge to the external platform participant.
- **Shadow identities over anonymous bridging:** External platform participants don't have SCP identities. Shadow identities give them protocol-level representation (with provenance) rather than attributing everything to the bridge operator. Shadows are restricted by default (observer role) to prevent capability escalation through bridges.
- **One-way claiming:** Once a shadow is claimed (bound to an identifier via identity attestation), the binding is permanent. This prevents identity confusion and simplifies attribution — historical actions are retroattributed once and for all.
- **Four modes for different integration depths:** Relay (read-only mirroring), Puppet (bridge acts on behalf of external user), Api (platform API integration), Cooperative (native SCP support on external platform). Each mode has different trust implications visible before opt-in.

### Implementation

- **Language:** Rust
- **Crate:** `scp-core` (bridge protocol types), `scp-bridge/*` (per-platform implementations)
- **Module:** `scp-core/bridge/`

### Dependencies

- **ADR-008 (Context Governance):** Bridge registration requires context governance approval. Bridge revocation is a governance action.
- **ADR-003 (identity attestation):** Shadow claiming uses identity attestation (§3.5) to bind an external handle to an identifier.
- **ADR-019 (Data Provenance):** All bridged content carries `BridgeProvenance` extending `DataProvenance`.
- **ADR-011 (Event Log):** Bridge registration, shadow creation, and claiming are context events.

### Acceptance Criteria

1. **Key types:**

```rust
pub struct BridgeConnector {
    pub bridge_id: String,
    pub operator_did: [u8; 32],
    pub platform: String,
    pub mode: BridgeMode,
    pub status: BridgeStatus,
    pub registration_context: ContextId,
    pub registered_at: u64,
}

pub enum BridgeMode {
    Relay,        // Read-only mirroring from external platform
    Puppet,       // Bridge acts on behalf of external users
    Api,          // Platform API integration
    Cooperative,  // Native SCP support on external platform
}

pub enum BridgeStatus {
    Active,
    Suspended,
    Revoked,
}

pub struct ShadowIdentity {
    pub shadow_id: String,
    pub platform_handle: String,
    pub bridge_id: String,
    pub attributed_role: String,     // Default: "observer"
    pub provenance_status: ShadowProvenanceStatus,
    pub created_at: u64,
}

pub enum ShadowProvenanceStatus {
    Shadow,   // Unclaimed — attributed via bridge
    Claimed,  // Bound to an identifier via identity attestation
}

/// Extension of DataProvenance for bridged content.
pub struct BridgeProvenance {
    pub base: DataProvenance,
    pub originating_platform: String,
    pub bridge_connector_id: String,
    pub operator_did: [u8; 32],
    pub bridge_mode: BridgeMode,
    pub shadow_status: ShadowProvenanceStatus,
}

pub struct ClaimRequest {
    pub shadow_id: String,
    pub claimant_did: [u8; 32],
    pub platform_handle: String,
    pub identity_attestation: Attestation,  // §3.5 attestation binding handle to identifier
    pub timestamp: u64,
    pub signature: P256Signature,
}

// claim_shadow returns Result<ShadowClaimEvent, ClaimError>

pub enum ClaimError {
    HandleMismatch,
    AttestationInvalid,
    AlreadyClaimed,
    ShadowNotFound,
}
```

2. **Bridge registration:**
   - The operator presents a registration request to context governance.
   - Context governance approves or rejects. The approver must be a different identity from the operator (self-approval is forbidden).
   - Registered bridge visible in context metadata (visible before opt-in, per legibility tenet).
   - Registration is a context event in the Merkle log.

3. **Shadow identity creation:**
   - Bridge creates protocol entity per external platform participant.
   - Shadow carries platform handle, bridge reference, and operating mode.

4. **Shadow default role:**
   - Observer-equivalent with restricted capabilities.
   - Cannot exercise capabilities requiring verified identity.
   - Specific role upgradeable by context governance.

5. **Provenance marking:**
   - All actions/content attributed to shadow identities carry `BridgeProvenance`.
   - `BridgeProvenance` includes: originating platform, bridge connector ID, operator identifier, operating mode, shadow/claimed status.
   - No shadow action mistakable for native SCP action.

6. **Trust hierarchy (two axes per §12.5):**
   - Native identity + native transport (strongest).
   - Native identity + bridged transport.
   - Claimed shadow + historical bridged.
   - Shadow + bridged (weakest).
   - Both identity confidence and transport confidence factor into evaluation.

7. **Shadow claiming:**
   - Claimant publishes identity attestation (§3.5) binding an external handle to its identifier.
   - Protocol verifies attestation matches shadow's platform handle.
   - Shadow retired, historical actions retroattributed to the claimant's identifier.

8. **Claiming is one-way and irreversible:**
   - Claimed shadow cannot be unclaimed.
   - Claimed shadow cannot be re-assigned to a different identity.

9. **Bridge revocation:**
   - Context governance removes bridge at any time.
   - Severing bridge disconnects all shadow identities from external platform.
   - Shadows retain their attributed actions but can no longer receive/send.

10. **Context isolation:**
    - Bridge in Context A has zero access to Context B.
    - Same platform bridged into two contexts = two separate bridge instances with separate registrations.

11. **Self-hosted bridges:**
    - Protocol treats self-hosted and managed identically.
    - Self-hosted eliminates third-party credential delegation (puppet mode).

### Scope

**Files (~5):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `BridgeConnector`, `BridgeMode`, `ShadowIdentity`, re-exports |
| `registration.rs` | Bridge registration, governance approval, context metadata integration |
| `shadow.rs` | Shadow identity creation, role management, provenance status |
| `claiming.rs` | `ClaimRequest`, `ClaimError`, attestation verification, retroattribution |
| `provenance.rs` | `BridgeProvenance`, provenance marking for bridged content |

Per-platform bridge adapter implementations are built on these primitives.

**Estimated functions:** ~15 public functions, ~10 internal helpers.
