# 7. Trust, Validation, and Capabilities

## 7.1 Design Principle: Validate, Minimize Trust

The protocol's security model is not built on trust. It is built on maximizing the surface area of what can be independently verified, so that trust is required only where validation is impossible.

Trust is a vulnerability. Every claim that requires trust to accept is a claim that can be exploited. The protocol's goal is to push claims down from the trust layer into the validation layer — replacing "someone says X" with "the protocol can verify X" at every opportunity.

The system has four layers, from hardest (pure validation) to softest (pure judgment):

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: PROTOCOL ENFORCEMENT (zero-trust, mandatory)       │
│                                                               │
│  Two-tier capability validation:                             │
│  Tier 1 — Full UCAN chain validation at token presentation  │
│    boundaries (role assignment, cross-context outlet           │
│    invocation, broadcast admission).                         │
│  Tier 2 — Capability cache check at intra-context operation │
│    time (derived from validated UCAN tokens, updated        │
│    atomically on role change).                               │
│  Revocations honored. Capability ceilings enforced over     │
│  every attestation in a token.                              │
│                                                               │
│  100% validation. 0% trust. No exceptions.                   │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: BEHAVIORAL VALIDATION (automated, objective)       │
│                                                               │
│  Verifiable event logs (Merkle trees per context).           │
│  Participation records derived from protocol events.            │
│  Outlet verification via deterministic testing.                │
│  Challenge-response for testable agent capabilities.         │
│  Threshold attestation counting.                             │
│  Consequence mechanism evaluation.                           │
│  Attestation freshness / time-locked renewal.                │
│                                                               │
│  Mostly validation. Minimal trust.                           │
│  This layer GROWS as the network accumulates history.        │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: ATTESTATION AUTHENTICITY (automated, signatures)   │
│                                                               │
│  Attestation signatures verified. Evidence checked where     │
│  objectively checkable (OAuth proofs, DNS records, hashes).  │
│  Claims are verified as REAL (really signed by who they      │
│  claim). Not verified as TRUE.                               │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4: TRUST EVALUATION (agent-level, subjective)         │
│                                                               │
│  Endorsement weighting. Judgment calls.                      │
│  Required for: new identities with no history,               │
│  non-testable capabilities, novel situations.                │
│                                                               │
│  This layer SHRINKS as participation validation grows.          │
│  Trust is the bootstrap. Validation is the steady state.     │
└─────────────────────────────────────────────────────────────┘
```

The critical property: **the trust surface shrinks over time.** New identities start trust-heavy — no participation history, need endorsements, can't be validated beyond their signatures. As they participate, participation records accumulate, outlet interactions are verified, challenge-responses are completed. The validation layers grow. Trust becomes supplementary, then marginal.

## 7.2 Layer 1: Protocol Enforcement

Every protocol action is zero-trust. Capability enforcement uses a two-tier validation design:

### 7.2.1 Tier 1: Full UCAN Chain Validation

Full 11-step UCAN validation (ADR-016 criterion 2) runs at **token presentation boundaries** — the points where a UCAN token is first introduced or must be re-verified:

- **Role assignment:** When a member is assigned a role, the assigner's `RoleAssign` capability is checked via cache, and `mint_role_tokens()` creates a capability token for each capability in the role definition. These tokens are the lightweight `context::roles::UcanToken` type (`iss`, `aud`, `att`, `nnc`) — a deliberately distinct type from the JWT-encoded `crypto::ucan::UcanToken` (`header`, `payload`, `signature`, `encoded`) that the 11-step pipeline consumes. They are validated against the context's capability ceiling at construction time — the same all-attestations rule applies at mint time (every capability in the role definition must be within the ceiling) and at presentation time (step 8) — and inserted directly into the `member_capabilities` cache. **They carry no per-token signature by design, and this is complete — not deferred.** The role token is never serialized as a bearer credential (the MLS leaf credential's `ucan_token` is `None` in all production paths), never crosses a trust boundary, and is structurally incapable of entering the Tier-1 pipeline (which accepts only the JWT `crypto::ucan::UcanToken`; there is no conversion path between the two types). Its authority is grounded in the signed source that performs the assignment — context creation for the creator's admin role, and the signed `AddMember`/`AssignRole` governance action (the `SignedVote` approval chain executed by `system_assign_role`) for every subsequent assignment — and, when role state is synced, in the signed context snapshot (ADR-050) that carries it. Each member derives its own `member_capabilities` cache locally from these signed governance events, so a capability cannot be forged by presenting a token; a per-token signature would be redundant with the governance signature that already authorizes the assignment. See `assign_role()` in `context/roles.rs`.
- **Cross-context outlet invocation:** When one context invokes an outlet exposed by another context, the invoker presents a UCAN that is fully validated against the target context's ceiling and the invoker's delegation chain.
- **Broadcast admission:** Gated broadcast contexts (§5.14.4) require a valid `messages:read` UCAN from subscribers. The full validation pipeline runs on the presented token. See `register_subscriber()` in `context/broadcast.rs`.

The 11 validation steps are:

1. Parse the JWT-format UCAN token
2. Verify Ed25519 signature (resolving `kid` from DID document per ADR-039)
3. Verify delegation chain integrity (`prf` chain, each parent's `aud` matches child's `iss`)
4. Verify root issuer is the context creator's DID
5. Verify audience matches the presenting agent's DID (self-delegation valid with `fct.scp_key_scope`)
6. Verify capability match against required capability (with wildcard support)
   - 6b. Enforce the agent permission model (§4.9) on the presented token and on every parent the chain walk resolves out of its `prf`. Step 7 requires a child's `att` to be a subset of its parent's, so a parent may grant a capability the child never names, and a check that read the presented token alone would let a child launder its parent's Category A grant. Four rules run:
     1. Reject a Category A capability signed by `#agent`, and record a custody violation (§4.9.1 rule 1).
     2. Reject a capability reserved to `#0` whatever key signed the token (§4.9.1 rule 2).
     3. Reject a root token (empty `prf`) signed by `#agent` (§4.9.1, the `#active` criterion).
     4. When the signing key is `#agent`, reject any attestation outside the permission set `fct.scp_agent_permissions` grants (§4.9.2).
     
     Rules 1 and 2 ship in `enforce_ucan_category_a`, on the presented token and on every parent. Rule 1's rejection ships and its custody record does not — §27.4.7 of the attestations spec derives that absence as open question OQ-26. Rules 3 and 4 are what stories SCP-AB-023 through SCP-AB-034 of `.docs/prds/agent-binding.json` deliver; no code applies either one today. The count of validation steps stays at eleven: 6b narrows the `att` set that step 6 already read, so it belongs to step 6.
7. Verify attenuation (each delegation narrows or preserves, never widens)
8. Verify every capability the token grants is within the context's immutable capability ceiling — not only the invoked capability. The token's entire attestation set (`att`) is checked; a token carrying any out-of-ceiling attestation is rejected even if the invoked capability is itself within the ceiling.
9. Validate nonce format, freshness, and uniqueness (replay prevention, §9.5)
10. Check token CID against per-context revocation list
11. Verify expiry (`exp > now`) and not-before (`nbf <= now`)

### 7.2.2 Tier 2: Capability Cache Check

At **intra-context operation time**, the protocol uses a derived capability cache (`member_capabilities` in `ContextRoleState`) rather than re-running the full 11-step pipeline on every action. This cache is:

- **Derived from ceiling-validated UCAN tokens:** The cache is populated exclusively from tokens minted by `mint_role_tokens()` during role assignment, which are validated against the context's capability ceiling at construction time. It is never populated from unvalidated sources.
- **Updated atomically on role change:** When `assign_role()` succeeds, the member's cached capabilities are replaced with the new role's capability set in the same operation. There is no window where stale capabilities are served.
- **Checked on every operation:** Every context operation — `send()`, `invoke_outlet()`, `close_context()`, governance actions — checks the cache via `member_has_capability()` before proceeding. A member without the required capability in cache is denied.

Operations that check the cache include:
- Message send: requires `MessagesWrite`
- Query outlet invocation: requires `OutletQuery(outlet_id)` or `OutletQueryAll`
- Action outlet invocation: requires `OutletCall(outlet_id)` or `OutletCallAll`
- Context close: requires `ContextClose`
- Role assignment: requires `RoleAssign`
- Member operations: requires `MemberInvite`, `MemberRemove`, etc.
- Governance: requires `GovernancePropose`, `GovernanceVote`

**Cache risk — cross-context revocation:** The capability cache is local to each context's `ContextRoleState`. If a future protocol extension adds cross-context UCAN revocation (revoking a token from outside the context where it was issued), the local cache would not reflect the revocation until the next role reassignment or cache refresh. Current revocation (§9.12 step 3, `revoke.rs`) is intra-context only — revocations are distributed as MLS application messages within the context and checked at Tier 1 boundaries. This is architecturally sound for the current design but would need a cache invalidation mechanism if cross-context revocation is added.

### 7.2.3 Security Properties

No action proceeds on reputation or identity alone. A trusted DID whose cached capabilities do not include the required permission is denied. An unknown DID whose role assignment granted the required capability (via validated UCAN) is permitted.

- For paid actions: spending UCAN is present and covers the cost (§19.5). Action UCAN + spending UCAN are AND-composed — both required.
- Tier 1 provides cryptographic proof of authorization at trust boundaries.
- Tier 2 provides O(1) capability lookup for the hot path of every intra-context operation.

This two-tier design is not a relaxation of security. Tier 2 checks are derived from Tier 1 validation — they are a performance optimization that preserves the security invariant. Every capability in the cache traces back to a cryptographically authorized source: externally-presented tokens (cross-context outlet invocation, broadcast admission) are validated through the full Tier-1 UCAN chain, and role-derived capabilities trace to the signed governance authorization that granted the role (context creation for the creator; the signed `AddMember`/`AssignRole` governance action thereafter). The role-derived `member_capabilities` entries are local materializations of that signed authorization, not independently-presented bearer tokens.

**Capability tokens** are fine-grained, per-context, per-capability. Build on UCAN (User Controlled Authorization Networks). Under the shared-DID model (ADR-039), intra-DID delegation uses self-delegation UCANs where `iss == aud` (same DID), the issuing key is `#active`, and `fct.scp_key_scope: "#agent"` scopes the delegation to the agent verification method. Tokens are independently revocable — you can revoke one capability from one agent in one context without affecting anything else. The UCAN chain provides verifiable delegation: the protocol can trace any token back to the root authority that granted it.

**`Custom(String)` capabilities** extend the built-in capability set. Custom capabilities use the `{resource}:{action}` format and are subject to the same ceiling enforcement — a custom capability must be in the context's capability ceiling to be exercised. To be a valid ceiling entry, a custom capability MUST be well-formed per the ceiling-entry grammar (§5.3.1.1), which is the authoritative definition of the permitted charset: `{resource}` and `{action}` are non-empty kebab-case tokens (`[a-z0-9-]+`, no `:`, no `*`, no whitespace) separated by **exactly one** colon, with the asterisk permitted **only** as the whole action segment of an explicit `{resource}:*` wildcard (never in the resource position, never as a substring). A bare single-token custom with no action (e.g. `payments`) is **not** a valid ceiling entry — there is no implicit wildcard — and is rejected at context creation with `InvalidCeilingCategory` (§5.3.1). A custom entry is additionally valid only if it does not name a built-in capability under any spelling — enforced by canonical resolution: resolving the entry's string through the protocol's canonical capability parser must not yield a built-in (§5.3.1.1). A custom `{resource}:*` wildcard is **further** rejected when `{resource}` is the resource token of any built-in capability (e.g. `member:*`, `messages:*`, `governance:*`): canonical resolution does not catch this (no `member:*` built-in exists) but ceiling wildcard coverage would let such an entry silently grant the privileged built-in actions in that family (e.g. `member:ban`) — closed by construction over the built-in resource-token set (§5.3.1.1 "No built-in-resource wildcard shadow"); a non-wildcard custom action under a built-in resource (e.g. `member:promote`) and a wildcard over a non-built-in resource (e.g. `payments:*`) both remain valid. Ceiling-entry strings are subject to the same string sanitization (§9.1A) and 256-byte length cap as other context string fields (§9.1A "String field validation" table in §5.9). Delegation and attenuation of custom capabilities follow the standard UCAN URI structure (`scp:ctx:{context_id}/{resource}:{action}`), so custom capabilities compose with the delegation chain exactly like built-in capabilities.

### 7.2.4 Structured Capability Evaluation: Gate vs. Diagnostic

Tier-1 validation (§7.2.1) has two callers with different needs, and the protocol exposes a distinct operation for each. They run the **same** 11 checks; they differ in what they return and in their side effects. (Decision: ADR-059.)

- **The enforcement gate.** At a token-presentation boundary the protocol either admits the action or rejects it. This is the throwing gate: it returns success or a single failure, fails closed, and **records the token's nonce** as a side effect of step 9 (replay defense, §9.5). It is the only operation permitted to authorize an action.
- **The structured diagnostic.** A caller deciding whether to proceed — surfacing a trust signal — needs to know *which* checks pass, not merely whether the whole token would be admitted. This is the read-only diagnostic: it returns a structured per-check result and **never enforces, never throws, and records no state.** In particular it probes the nonce read-only (it never records it), so it is safe to call repeatedly on the same token without consuming the token's nonce.

**The challenge capability is mandatory for the gate and OPTIONAL for the diagnostic.** The enforcement gate always authorizes *for* a specific invoked capability, so its `required_capability` is mandatory. The diagnostic admits two modes:

- **No challenge (intrinsic-validity mode).** The diagnostic evaluates the token's intrinsic validity — every check above EXCEPT the invoked-capability grant-match (step 6), which is skipped. This is the mode a trust signal uses when assessing a participant's tokens for *general* validity, where there is no specific capability to challenge. Omitting the challenge MUST be fail-closed: every other check still runs (notably the all-attestation ceiling of step 8, over the token's own `att` set), and omitting the grant-match MUST NOT cause any per-check field to report `true` that another check would report `false`.
- **With a challenge.** The diagnostic additionally requires that the token grants the supplied capability (step 6), exactly as the gate does.

The absence of a challenge is expressed by *omitting the capability* — NOT by a wildcard or "match anything" sentinel (a bare `*` is a malformed capability URI and is rejected at parse time). The gate never admits an absent capability.

**The structured capability-evaluation result is the canonical way a caller obtains a per-check breakdown.** It is a flat record of six independent booleans, one per pipeline stage group, mapping onto the 11 steps of §7.2.1:

| Field | Stage(s) of §7.2.1 | Meaning when `true` |
|-------|--------------------|---------------------|
| `tokens_valid` | step 1 | The token parsed and its header validated, and the attestation set parsed into capability URIs (fail-closed: any unparseable attestation makes this `false`). |
| `signatures_valid` | steps 2–7 | Signature, full delegation chain (every parent's signature/expiry/revocation), root issuer, audience, key scope, the invoked-capability grant-match, Category-A enforcement, and attenuation all passed. The invoked-capability grant-match (step 6) runs only when a challenge capability is supplied; in the diagnostic's intrinsic-validity mode it is skipped and this field reflects only the structural checks. |
| `within_ceiling` | step 8 | Every capability the token grants — the whole `att` set, not only the invoked capability — is within the context's immutable ceiling. This check is over the token's own `att` set and is independent of any challenge capability. When a challenge was supplied, reaching this stage also implies the step-6 grant-match passed; with no challenge, it implies only that no attestation exceeds the ceiling. |
| `nonce_valid` | step 9 | Nonce format, freshness, and uniqueness passed — **probed read-only; the nonce is NOT recorded.** |
| `not_revoked` | step 10 | The token's revocation CID is not on the context revocation list. |
| `time_bounds_valid` | step 11 | `exp`/`nbf` time bounds are valid within clock-skew tolerance. |

The result is **strictly ordered and short-circuiting**, mirroring the gate: a field is `true` only if its stage ran *and* passed; the first failing stage and every later stage are `false` (a later stage never ran, so nothing about it is known to be valid). Two consequences follow and are normative for any consumer:

- `signatures_valid` covers the **whole** delegation chain, not just the leaf. An otherwise-valid leaf whose *parent* is expired or revoked reports `signatures_valid: false` — not `time_bounds_valid: false` / `not_revoked: false` (those two reflect only the leaf token).
- The result is a **point-in-time snapshot, not a pre-flight guarantee.** `nonce_valid: true` and `not_revoked: true` can both flip to a rejection at enforcement time if, between the diagnostic call and the gate call, the nonce is recorded by another request or the token is revoked. The diagnostic is a trust signal, never a promise that the gate will admit.
- A diagnostic result is **never an authorization decision.** Only the throwing gate (with its mandatory challenge capability) may authorize an action. In particular, an intrinsic-validity result (no challenge capability) deliberately skips the invoked-capability grant-match (step 6), so an all-`true` result does NOT establish that the token grants any particular capability — it attests only intrinsic validity. Gating an action on a no-challenge diagnostic result is a misuse: re-run the throwing gate with the concrete capability.

**SDK consumption (normative).** SDKs expose the structured result and obtain per-check outcomes from it. An SDK MUST NOT derive *which check failed* by parsing the human-readable prose of an error message — the structured result is the only sanctioned source of the per-check breakdown. Where an SDK must classify a thrown gate error into a typed SDK error, it does so from the bridge error-code taxonomy (the stable `[SCP-CAT-NNNN]` codes), surfaced through a single mapping site, not by inspecting message text at each call site. The structured-result shape is identical across all bindings (only field casing follows each language's convention); the public wrapper that exposes it is per-SDK idiomatic. See ADR-059 for the decision, its rationale, and the rejected alternatives (notably: prose-parsing, and overloading the throwing gate to also return structure), and the lesson `.docs/lessons/sdk-consume-structured-ffi-results-not-error-prose.md` for why prose-parsing is a recurring failure mode and how it is prevented.

## 7.3 Layer 2: Participation Validation

This is the layer that replaces trust with evidence. It grows as the network accumulates history, and it is the primary mechanism by which SCP minimizes trust dependencies over time.

### 7.3.1 Verifiable Event Logs

Every context maintains a verifiable event log — a Merkle tree (or equivalent authenticated data structure) of the context's convergent protocol events: membership changes, role assignments, governance actions, lifecycle, access, and provenance (the MLS-commit-ordered stream; ADR-011). Attestations are NOT context-log events: they are credential-layer artifacts (DID-document entries, relay-published blobs, the `TrustProtocolRepository` cache; §7.4), each verified by its own envelope signature and revocation status rather than by inclusion in the context Merkle tree. Application events — messages and outlet invocations — are per-author and enter this convergent log under the causal-DAG ordering of ADR-051; until then they are local `ContextEvent`s, not canonical leaves (see the ADR-011 amendment, exclusion taxonomy). Events are signed by the acting agent.

**Event sequencing mechanism.** Events in the Merkle tree are sequenced using a per-context monotonic counter maintained by the context's governance authority (admin in SingleAdmin; the committing member in other models). Sequence numbers are 64-bit unsigned integers starting at 0, incremented by 1 for each event. The counter is stored at `context/{context_id}/event_meta/count` (§17.3). Concurrent events from different members are serialized through the MLS commit mechanism — only one Commit can succeed per epoch, and the committing member assigns the sequence number. In broadcast contexts, each author maintains their own sequence counter (independent per-author sequencing). The canonical Merkle leaf is `leaf_hash = SHA-256(0x00 ‖ rmp_serde(Event))` over the typed `Event` (ADR-011 / §25), whose serialized fields include the event type, actor DID, timestamp, and payload; commit-ordered events also carry the committer-assigned sequence, while DAG-ordered application events carry causal head-references in its place (ADR-051). The leaf `timestamp` is assigned the same way as the sequence: for a commit-ordered event the committing member sets it to the `created_at` of the signed SCP envelope carrying the commit (§9.8.2), and every member copies that one committer-assigned value into its own leaf — it is not each member's local wall-clock reading. All honest members therefore hold byte-identical leaf preimages for the same event, so the timestamp is a value *assigned-and-propagated*, not a current time each member reads independently; it is tamper-evident (covered by the committer's envelope signature and by the leaf hash) and bounded to real time within the clock-skew tolerance of §9.8.2 (the ±5-minute future bound). For events triggered by a local timer rather than a commit — TTL expiry/close, governance-freeze expiry, and deferred economic-policy application — the convergent timestamp is the pre-computed deadline already held in convergent context state (the TTL deadline, the freeze-expiry instant, the policy-application time), never local `now()`. Convergence of the leaf depends on this rule: leaves stamped with per-member-local times would diverge and break the equal-event-count ⇒ equal-Merkle-root property the Relay Consistency Protocol relies on (§9.9.3).

Any participant can verify claims about context history against the Merkle root:

- "This outlet was registered on date X by DID Y" — verifiable via proof-of-inclusion.
- "The context's capability ceiling has not changed since creation" — verifiable via the log's mutation history.
- "Carol has never had a governance action taken against her in Context A" — verifiable by querying the log for governance actions with `subject == Carol's DID` and receiving an empty result set. Note: this is an exhaustive query against the log, not a cryptographic proof-of-absence. Standard append-only Merkle trees support proof-of-inclusion (a leaf exists) but do NOT support proof-of-absence (a leaf does not exist). A negative claim ("no governance action exists") is verified by the querier scanning the log and confirming no matching events are found. The Merkle root ensures the log has not been tampered with — if an event was recorded, it cannot be removed — but the protocol does not provide a single compact proof that a specific event type was never recorded. Consumers who require cryptographic proof-of-absence (rather than query-and-verify) SHOULD use a sparse Merkle tree or sorted Merkle tree with boundary proofs; the protocol does not mandate a specific authenticated data structure beyond the general requirement of Merkle-based integrity (§7.3.1 header: "Merkle tree (or equivalent authenticated data structure)").

This transforms claims about the past from trust-dependent to validation-dependent. You don't need to trust a context admin's account of what happened — you verify it against a cryptographic data structure.

### 7.3.2 Participation Records

The protocol defines a standard participation record format whose facts are derived from context event logs, with one exception called out below (attestation history, which is a credential-layer fact — §7.4). A participation record is not a reputation score (opaque, gameable, subjective). It is a set of verifiable facts:

- Number of contexts participated in, with duration
- Outlet invocations by type and frequency
- Governance actions taken against this identity (warnings, role demotions, ejections)
- Governance actions taken by this identity (if in a governance role)
- Role progression history (promotions, demotions)
- Attestation history (endorsements issued, endorsements received, endorsement accuracy) — the exception: NOT derived from context event logs but from the credential layer (§7.4); see `attestation_count` below
- Context creation history

Facts derived from convergent events — participation duration (`MemberJoined`/`MemberLeft`), governance actions (`GovernanceActionExecuted`), role progression (`RoleAssigned`), and context-creation (`ChildContextCreated`) — are convergent-by-construction: each becomes Merkle-verifiable against the relevant context's Merkle root once receive-side replication lands (ADR-051). Today the runtime emits these leaves committer-side only (receive-side replication is dormant), so a non-committer's locally-derived record is committer-local rather than independently Merkle-verifiable until ADR-051. **`attestation_count` is the explicit exception: it is NOT a context-event fact and NOT Merkle-anchored.** Attestations are credential-layer artifacts (§7.4), not context-log leaves; `attestation_count` is computed on-demand from the attestations the verifying agent can access, and each contributing attestation is verified by its own envelope signature and revocation status (§7.4.4), not by inclusion in any context Merkle tree (see the per-context-extraction step for `attestation_count` below). The `outlet_invocation_count` fact derives from `OutletInvoked`, per-author application activity that becomes Merkle-anchored under the causal-DAG ordering of ADR-051 (computed locally until then; see the ADR-011 amendment, exclusion taxonomy). The participation record is not stored centrally — it is computed by any agent from the set of context logs and accessible attestations.

**Participation record computation algorithm.** An agent computing a participation record for a target DID across N accessible context logs follows this deterministic procedure:

1. **Enumerate contexts.** List all context logs the computing agent can access that contain membership events for the target DID.
2. **Per-context extraction.** For each context log, scan events matching the target DID and extract:
   - `participation_duration_secs`: `(latest_event_timestamp - MemberJoined_timestamp)` for the target DID. If the member has left and rejoined, sum all intervals. The `MemberJoined`/`MemberLeft` leaves carry the affected member's DID in their payload (the membership-change payload, ADR-011), so for admin-driven joins/removals the interval is attributed to the affected member rather than to the admin who executed the action; on self-join and broadcast-author paths the leaf `actor_did` is already the member itself. For the context creator (founder), the seeding `MemberJoined` leaf timestamp is the creator-assigned context-creation timestamp — so the founder's duration is creator-timestamp-trusting, and like every membership-derived fact it is committer-local until ADR-051 receive-side membership replication lands (no independent receiver corroborates the creator's clock before then).
   - `governance_actions_against`: Count of events with type `GovernanceActionExecuted` whose leaf **`target_did`** equals the target DID. `target_did` is the *targeted* member, carried in `GovernanceActionExecutedPayload` (and `AccessRevokedPayload` for access-revocation events) and surfaced by the projection's `target_did` field (ADR-011) — a field distinct from the role/membership `subject_did` field below: governance/access facts key on `target_did`, role/membership facts key on `subject_did`.
   - `governance_actions_by`: Count of events with type `GovernanceActionExecuted` whose leaf `actor_did` equals the target DID.
   - `outlet_invocation_count`: Count of events with type `OutletInvoked` whose leaf `actor_did` equals the target DID. (Per-author application activity: computed from local `ContextEvent`s, not the Merkle log, until ADR-051 makes `OutletInvoked` a convergent leaf; it needs the convergent DAG *count* — no clock.)
   - `context_creation_count`: Count of events with type `ChildContextCreated` whose leaf `actor_did` equals the target DID. This is per-context (counts child contexts created within this context only, not globally).
   - `role_progression_count`: Count of events with type `RoleAssigned` whose leaf **`subject_did`** equals the target DID. `subject_did` is carried in the `RoleAssigned` leaf payload (`RoleAssignedPayload`, ADR-011) and surfaced by the projection's separate `subject_did` field, so the affected member — not the assigning governance actor — is the subject this fact is attributed to.
   - `attestation_count`: counted from the **credential layer**, NOT from the context event log. There is no `AttestationPublished` event type — attestations are never context-log leaves (§7.4). The count is the number of endorsements issued/received for the target DID that the computing agent can access from the credential layer — DID-document attestation entries, relay-published attestation blobs, and the `TrustProtocolRepository` cache — filtered to currently-valid (non-revoked) attestations per §7.4.4. It is computed **on-demand** and is **verifier-relative**: two agents may compute different counts because they can access different subsets of the subject's attestations. It is **NOT Merkle-anchored** to any context event-log root; each contributing attestation is verified by its own envelope signature and revocation status (§7.4.1, §7.4.4), not by inclusion in a context Merkle tree.
3. **Deduplication.** The same DID in multiple roles in the same context counts as one context participation. Role changes within a context do not create duplicate entries.
4. **Aggregation.** Sum each fact across all contexts to produce the aggregate participation record. The aggregate is NOT signed — it is a local computation. Only per-context `ParticipationProfile` attestations (§7.3.2.1) are signed.
5. **Freshness.** Each fact carries the `updated_at` timestamp from its source context. Stale facts (older than the consumer's `max_age_secs` requirement) are excluded from the aggregate. Facts whose `updated_at` is implausibly far in the future — beyond the verifier's clock plus the §9.14 clock-skew tolerance (5 minutes) — are likewise excluded, so a future-dated timestamp cannot read as maximally fresh and evade the `max_age_secs` window.

Participation records replace endorsements as the primary input to evaluation for established identities. Instead of "Bob says Carol is trustworthy for scheduling," the evaluating agent can see: "Carol has invoked scheduling outlets 203 times across 14 contexts over 8 months. Zero governance actions. Three contexts promoted her to admin." These are facts, not opinions. Validated, not trusted.

#### 7.3.2.1 Participation Admission Requirements

Contexts MAY declare participation requirements for admission, enforced mechanically alongside capability requirements (§7.3.4.4). Participation admission transforms "do we trust this agent?" into "does this agent's verifiable history meet our criteria?" — pushing admission from Layer 4 (trust) into Layer 2 (participation validation).

**Core invariant:** Agents MUST NOT be able to write, modify, or delete their own participation statements. Contexts produce and host them. This is non-negotiable.

**Requirement structure:**

```
RequireParticipation {
    fact: ParticipationFact,          // which participation category
    threshold: ParticipationThreshold, // comparison + value
    max_age_secs: u64,             // record freshness requirement
    min_contexts: u32,             // from at least N independent contexts
}
```

**`ParticipationFact` categories** (corresponding to `ParticipationRecord` fields):

- `ParticipationDuration` — Total seconds of context participation (`participation_duration_secs`).
- `GovernanceActionsAgainst` — Count of governance actions taken against the identity (`governance_actions_against`).
- `GovernanceActionsBy` — Count of governance actions initiated by the identity (`governance_actions_by`).
- `OutletInvocationCount` — Total outlet invocations across all outlet types (`outlet_invocation_count`).
- `ContextCreationCount` — Number of contexts created (`context_creation_count`).
- `RoleProgressionCount` — Number of role transitions (`role_progression_count`).
- `AttestationCount` — Number of currently-valid endorsements the verifying agent can access for the subject from the credential layer (`attestation_count`; §7.4, not a context-event count — see `attestation_count` in §7.3.2).

**`ParticipationThreshold` operators:**

- `GreaterThan(u64)` — Fact value must be strictly greater than the specified value.
- `LessThan(u64)` — Fact value must be strictly less than the specified value.
- `AtLeast(u64)` — Fact value must be greater than or equal to the specified value.
- `AtMost(u64)` — Fact value must be less than or equal to the specified value.
- `Equals(u64)` — Fact value must equal the specified value exactly.

**Context-hosted participation statements:**

Contexts produce `ParticipationProfile` attestations for each member. Statements are full participation profiles — one statement per member per context, mutated in place (not appended). Whenever underlying facts change (governance action, role transition, outlet invocation milestone, etc.), the context updates the member's statement and re-signs it.

Each `ParticipationProfile` contains all 7 participation fact categories:

```
ParticipationProfile {
    subject_did: DID,                  // who this is about
    participation_duration_secs: u64,  // total seconds of context participation
    governance_actions_against: u64,   // governance actions taken against this identity
    governance_actions_by: u64,        // governance actions initiated by this identity
    outlet_invocation_count: u64,        // total outlet invocations
    outlet_invocation_count_anchored: bool, // false until ADR-051: derived from local ContextEvents, not the Merkle log — consumers MUST NOT treat as Merkle-proven
    context_creation_count: u64,       // contexts created
    role_progression_count: u64,       // role transitions
    attestation_count: u64,            // credential-layer count (§7.4): endorsements issued/received the signer can access, currently-valid (non-revoked) — NOT a context-event count, NOT verifiable against event_log_root
    updated_at: u64,                   // timestamp of last update
    event_log_root: [u8; 32],         // Merkle root; convergent-derived facts verifiable against it (outlet_invocation_count is context-signed-only until ADR-051; attestation_count is a credential-layer fact and is NOT covered by this root)
    // NOTE: no context_id — this is the privacy guarantee
    signer_public_key: [u8; 32],      // context-specific signing key
    signature: Ed25519Signature,       // over all signed fields above
}
```

The signed `ParticipationProfile` does NOT carry an `attestation_count_anchored` field. `attestation_count` is a verifier-relative credential-layer claim count that is PERMANENTLY non-anchored (no attestation event type; §7.4), so a per-profile boolean would be a tamperable constant on a signed struct. Instead, the permanently-`false` anchoring status is exposed only on the UNSIGNED facts / `BehavioralRecord` projection that downstream consumers read (the parallel of `outlet_invocation_count_anchored`, which — unlike this one — IS a signed field because it can become `true` under ADR-051). Consumers reading that projection MUST treat `attestation_count` as never Merkle-anchored.

The `signer_public_key` is context-specific — derived from the context's identity with domain separation, not reused across contexts. This prevents the verifier from correlating which contexts share a signer. The signature covers all fields except itself.

**Signer key derivation.** The context's participation signing key is generated from a `participation_signing_seed` — a random 32-byte value created once at context creation time and stored in the context's governance state. This seed is independent of any admin's identity key, ensuring that admin rotation does not invalidate historical participation statements.

```
participation_signing_seed = CSPRNG(32)          // generated once at context creation
salt = SHA-256("SCP-PARTICIPATION-SIGNER-V1")    // fixed salt, 32 bytes
info = "scp-participation-signer:" || context_id // context_id as UTF-8 bytes
prk = HKDF-Extract(salt, participation_signing_seed)  // 32 bytes
okm = HKDF-Expand(prk, info, 32)                // 32 bytes — Ed25519 seed
signer_keypair = Ed25519::from_seed(okm)
```

The `signer_public_key` in the `ParticipationProfile` is the public half of this derived keypair. Each context produces a unique signing key deterministically from its seed, so verification is possible by anyone who receives the statement — but the verifier cannot reverse-derive the context ID from the public key (one-way derivation).

**Seed custody and admin rotation.** The `participation_signing_seed` is stored encrypted in the context's governance state, wrapped to the current admin's `#0` identity key using HPKE (X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20Poly1305) with info string `"scp-participation-seed-wrap:" || context_id`. During admin rotation, the outgoing admin MUST re-wrap the seed to the incoming admin's `#0` key and include the re-wrapped seed in the `AdminRotation` governance event. The incoming admin unwraps the seed and can then produce and sign participation statements. If the outgoing admin is unavailable (e.g., key compromise), the seed is lost and a new seed MUST be generated — this invalidates all prior statements from this context, which is the correct security behavior when admin continuity is broken.

**Participation signing key rotation.** The `participation_signing_seed` itself can be rotated independently of admin rotation via the `RotateParticipationKey` governance action. This generates a new random seed, derives a new signing keypair, re-signs all outstanding participation statements with the new key, and publishes a `ParticipationKeyRotated` event containing the new `signer_public_key`. Verifiers who cached the old public key MUST accept both old and new keys for a 30-day overlap period (matching the statement `max_age_secs` default). After the overlap period, only the new key is valid for newly-signed statements. Historical statements signed with the old key remain valid if their `updated_at` predates the rotation event.

**Context-hosted storage model:**

Statements are stored on source context relays. The context controls the storage. The agent cannot write, modify, or delete statements — this is the critical integrity guarantee. When a member's participation facts change, the context re-computes and re-signs the statement, replacing the prior version in place.

**DID document service endpoint:**

Each agent's DID document lists a `ParticipationStatements` service endpoint that points to a relay or aggregation endpoint where their statements can be fetched by verifiers. This is the discovery mechanism — admitting contexts resolve the agent's DID, find the service endpoint, and fetch statements from it. The endpoint type MUST be listed in the DID document service endpoint cross-reference table (§18.2.2).

**ParticipationStatements service endpoint format.** The DID document entry:

```json
{
  "id": "#scp-participation",
  "type": "ParticipationStatements",
  "serviceEndpoint": "https://relay.example.com/scp/v1/participation/<did>"
}
```

The `serviceEndpoint` URL accepts HTTP GET requests. Authentication is not required — statements are public (privacy is achieved by omitting `context_id` from statements, not by restricting access). The response is a JSON array of signed `ParticipationProfile` objects:

```
GET /scp/v1/participation/{did}
Accept: application/json

Response 200 OK:
{
  "statements": [
    {
      "subject_did":                "<DID>",
      "participation_duration_secs": 86400,
      "governance_actions_against":  0,
      "governance_actions_by":       2,
      "outlet_invocation_count":       203,
      "context_creation_count":      1,
      "role_progression_count":      3,
      "attestation_count":           5,
      "updated_at":                  1709654400,
      "event_log_root":             "<32 bytes, hex-encoded>",
      "signer_public_key":          "<32 bytes, hex-encoded>",
      "signature":                  "<64 bytes, hex-encoded>"
    }
  ],
  "total": 7,
  "did": "<DID>"
}
```

**Filtering.** The endpoint supports optional query parameters: `?min_updated_at={unix_timestamp}` (only statements updated after this time), `?limit={n}` (max statements to return, default 100, max 1000), `?offset={n}` (for pagination). Statements are returned sorted by `updated_at` descending (most recent first).

**Caching.** The endpoint SHOULD set `Cache-Control: public, max-age=300` (5 minutes). Verifiers SHOULD cache responses per DID to avoid repeated fetches during admission evaluation.

**Colluding contexts participation forgery mitigation.** A single operator running N contexts can produce N distinct `signer_public_key` values and generate `ParticipationProfile` statements for their own DID, trivially satisfying `min_contexts` requirements. The protocol addresses this through layered defenses:

1. **DeviceAttestation binding (primary).** Contexts requiring strong Sybil resistance SHOULD require `DeviceAttestation` (§9.3) from attestors. Since each hardware device produces at most one attestation, a single operator cannot fabricate N hardware-attested contexts from one machine.
2. **Statement age depth.** Admission requirements include `max_age_secs` and consumers can additionally require `participation_duration_secs >= T` (e.g., 30 days). Manufacturing fake participation over extended durations requires sustained resource expenditure (contexts must remain operational and active for the full duration).
3. **Cross-statement correlation analysis (RECOMMENDED).** Consumers SHOULD analyze statement timing: N statements all with identical `updated_at` values (or timestamps within seconds of each other) suggest automated batch generation. Consumers MAY discount or reject statement sets with suspiciously correlated timing.
4. **Transparency logging.** Each statement includes an `event_log_root` that commits to the context's full event log. A verifier who discovers that the event log behind a root contains only synthetic events (e.g., only the subject DID's activity, no other participants) can flag the statement as potentially fabricated.
5. **Cost of attack.** Each fake context requires relay storage, DID publication, and ongoing maintenance. The economic cost scales linearly with N. Combined with context-level economic policy (§19), maintaining fake contexts has ongoing financial costs.

These defenses do not eliminate Sybil attacks — they raise the cost until the attack becomes economically irrational for the value of the admission being sought. Contexts requiring absolute Sybil resistance should use additional admission mechanisms (endorsements from known parties, identity link attestations to established external accounts).

**Opt-in model:**

Agents opt into per-context attestations by allowing the context to publish participation statements about them. This is the privacy control — agents choose which contexts can publish participation data. A context MUST NOT publish a `ParticipationProfile` for a member who has not opted in. Opting out means the context does not produce or store a statement for that member, but also means the member cannot present participation evidence from that context when seeking admission elsewhere.

**Verification flow:**

1. Context declares one or more `RequireParticipation` entries in `ContextParams` admission requirements.
2. Joining agent sees the requirements in context metadata before opting in (legibility tenet — visible before join decision).
3. Admitting context resolves the agent's DID document and finds the `ParticipationStatements` service endpoint.
4. Admitting context fetches statements from the service endpoint.
5. Admitting context verifies: (a) each statement's signed `subject_did` equals the DID of the agent being admitted — statements for any other subject are discarded before they can contribute to any threshold, freshness, or distinct-signer count (closing cross-subject participation-profile replay, where a victim's genuine high-standing profiles are presented to admit a different agent), (b) each statement's Ed25519 signature is valid over its fields, (c) signers are distinct (N different `signer_public_key` values — proving N independent contexts), (d) each required fact meets the required threshold, (e) each statement's `updated_at` is within `max_age_secs` of the current time, (f) statements span at least `min_contexts` distinct signers for each requirement.
6. If any requirement is not met, admission is denied.

All checks are mechanical — no judgment, no discretion, no governance vote. The admitting context verifies signed claims from distinct signers without ever learning which contexts produced them.

**Privacy properties:**

- Statements do NOT include `context_id` — the admitting context sees signed claims from distinct signers but **cannot identify which contexts** they correspond to. Context-specific signing keys derived with domain separation prevent correlation across contexts.
- The agent opts into which contexts publish statements — this is the privacy control. An agent can have statements from some contexts published while keeping other memberships private.
- The admitting context fetches from the agent's service endpoint, not from individual context relays. Traffic analysis at the relay level is not a meaningful risk at scale — popular relays serve thousands of contexts, and knowing a relay connection does not reveal specific context membership.
- The agent always has the option to not join if the requirements are unacceptable.

**Tamper resistance:**

- Agents CANNOT write, modify, or delete participation statements — contexts control the storage on their relays. The agent has no write access to the statement store.
- Statements are signed by context-specific Ed25519 keys — the agent cannot forge them.
- Context-specific keys are derived with domain separation so they cannot be correlated across contexts by the verifier.

**DDoS resistance:**

- The admitting context fetches from the agent's service endpoint — bounded by one fetch per admission attempt. No amplification vector.
- Source contexts only produce statements for opted-in members. No unauthenticated statement generation.
- Statement size is bounded: ~150 bytes per statement per context. 100 contexts = ~15KB (acceptable). 1000 contexts = ~150KB (served via the service endpoint, not inline in the DID document).

**Example admission policy:**

```json
{
  "participation_requirements": [
    {
      "fact": "GovernanceActionsAgainst",
      "threshold": { "AtMost": 0 },
      "max_age_secs": 7776000,
      "min_contexts": 3
    },
    {
      "fact": "ParticipationDuration",
      "threshold": { "AtLeast": 86400 },
      "max_age_secs": 2592000,
      "min_contexts": 1
    }
  ]
}
```

This says: "No governance actions against you in the last 90 days (verified via signed statements from at least 3 independent contexts), and at least 24 hours of total participation in the last 30 days (from at least 1 context)." Both are verifiable facts attested by context-specific signatures — the admitting context verifies the claims without learning which contexts produced them.

### 7.3.3 Outlet Verification

SCP outlets are stateless functions with broadly deterministic behavior — consistent behavior and output format for a given input, though not necessarily token-for-token identical output. An LLM-backed outlet that answers cooking questions in a consistent schema is "stateless" in the protocol's sense. This makes outlet integrity **testable** at the participation level.

When an outlet is registered with a context, the registration includes:

- Schema (input and output types, MCP-compatible JSON Schema)
- Implementation hash (content-addressable reference to the implementation)
- Test vectors (known input-output pairs that define correct behavior)
- Operator DID (who registered the outlet and is accountable for it)

Any agent can verify an outlet's integrity at any time by:

1. Calling the outlet with test vector inputs
2. Comparing outputs against expected values
3. Verifying the implementation hash hasn't changed since registration

Test vectors verify participation conformance and schema compliance, not exact string matching. An outlet that returns a correct answer in a valid schema passes, even if the phrasing differs between invocations. If outputs diverge from expected behavior: the outlet has been modified or compromised. Detectable, attributable to the operator.

Multiple agents verifying independently creates threshold confidence. If 10 agents all get expected outputs, the outlet is almost certainly behaving correctly. This is continuous validation, not a one-time trust decision.

Outlet mutations (new implementation hash, modified schema, changed test vectors) are context-level events recorded in the Merkle log, visible to all members. An agent can set its own policy: refuse to call outlets that have changed since it joined, accept changes from trusted operators, or require N independent verifications after any change.

### 7.3.4 Challenge-Response Verification

Self-reported agent capabilities can be challenged rather than trusted. The protocol defines standard challenge suites for testable capabilities.

An agent claims "prompt injection filtering: true" in its capability metadata. A context or peer agent can issue a challenge: a set of test cases that exercise the claimed capability. The challenged agent processes the tests and returns results. The challenger verifies the results demonstrate the claimed capability.

Properties:

- **Repeatable.** Challenges can be re-issued at any time. An agent that passed a challenge last month can be re-challenged today.
- **Standardized.** The protocol defines challenge suites for common capabilities (prompt injection resistance, schema validation, rate limit compliance, content formatting). Custom challenges are possible for context-specific capabilities.
- **Distinguishable.** Agent capability metadata distinguishes between self-attested capabilities (claimed but untested) and challenge-verified capabilities (tested and passed, with timestamp of last verification). Other agents can factor this distinction into their evaluation.

Not all capabilities are testable. "Good judgment" is not challengeable. But many defensive and functional capabilities are, and for those, challenge-response replaces trust with validation.

**ChallengeVerification record format.** A signed record proving that a specific verifier tested a capability and the agent passed:

```
ChallengeVerification {
  verification_id:  [u8; 32],          // SHA-256(verifier_did || subject_did || capability_uri || timestamp)
  verifier_did:     DID,               // who administered the challenge
  subject_did:      DID,               // who was tested
  capability_uri:   String,            // scp:capability:*/v1 or did:*:capability:*/v1
  suite_version:    String,            // version of the challenge suite used (e.g., "2026.1")
  passed:           bool,              // true = passed, false = failed
  score:            Option<u32>,       // optional numeric score (0-10000 basis points, 10000 = perfect)
  test_count:       u32,               // number of test cases administered
  pass_count:       u32,               // number of test cases passed
  timestamp:        u64,               // Unix timestamp of verification
  expires_at:       u64,               // verification validity period (MUST NOT exceed 90 days from timestamp)
  context_id:       Option<ContextId>, // context where challenge was administered (if applicable)
  verifier_signature: Ed25519Signature // verifier signs all fields above
}
```

**Storage and discovery.** `ChallengeVerification` records are stored in the subject's DID document as entries in the `SCPCapabilities` service endpoint, alongside self-attested capabilities. The record is also stored in the context's event log if the challenge was administered within a context. Verifiers fetch records from the subject's `SCPCapabilities` endpoint during admission checks (§7.3.4.4). Records are identified by `verification_id` for deduplication and revocation.

**Expiry.** Challenge verifications expire after the `expires_at` timestamp. The maximum validity period is 90 days — capabilities can degrade over time (model updates, configuration changes), so re-verification is necessary. Contexts MAY require shorter validity periods in their admission requirements.

**Challenge suite protocol.** The protocol for administering a challenge:

1. **Challenge initiation.** A verifier (context admin, peer agent, or dedicated verification service) sends a `ChallengeRequest` as an outlet call within a shared context:
   ```
   ChallengeRequest {
     challenge_id:    [u8; 32],        // random, unique per challenge session
     capability_uri:  String,          // which capability to test
     suite_version:   String,          // which version of the test suite
     test_cases:      Vec<TestCase>,   // the actual test cases
     timeout_secs:    u32,             // maximum time to complete all tests (default: 300)
     verifier_did:    DID,             // who is administering
   }

   TestCase {
     test_id:         String,          // unique within the suite
     input:           Value,           // JSON input to the agent
     expected:        ExpectedOutput,  // what constitutes passing
     category:        String,          // test category within the suite
     weight:          u32,             // importance weight (basis points, sum = 10000)
   }

   ExpectedOutput:
     | ExactMatch    { value: Value }                    // output must equal this value
     | SchemaMatch   { schema: JsonSchema }              // output must validate against schema
     | ContainsAll   { required: Vec<String> }           // output must contain all strings
     | ContainsNone  { forbidden: Vec<String> }          // output must contain none of these
     | CustomEval    { evaluator_outlet_id: OutletId }       // a registered outlet evaluates the output
   ```

2. **Challenge execution.** The challenged agent processes each `TestCase` and returns results:
   ```
   ChallengeResponse {
     challenge_id:    [u8; 32],        // matches the request
     results:         Vec<TestResult>,
     completed_at:    u64,             // Unix timestamp
     subject_signature: Ed25519Signature // subject signs the response
   }

   TestResult {
     test_id:         String,
     output:          Value,           // the agent's actual output
     duration_ms:     u64,             // time to produce this result
   }
   ```

3. **Verification.** The verifier evaluates each `TestResult` against the corresponding `TestCase.expected`:
   - `ExactMatch`: `output == expected.value` (deep equality after JSON normalization).
   - `SchemaMatch`: `output` validates against `expected.schema` (JSON Schema draft 2020-12).
   - `ContainsAll`: all `required` strings appear in the string representation of `output`.
   - `ContainsNone`: no `forbidden` strings appear in the string representation of `output`.
   - `CustomEval`: the evaluator outlet is called with `{ test_case, output }` and returns `{ passed: bool, reason: string }`.

4. **Result publication.** If the overall score meets the pass threshold (suite-specific, default: 8000 basis points = 80%), the verifier creates and signs a `ChallengeVerification` record. The record is published to the subject's service endpoint and optionally recorded in the context's event log.

5. **Timeout.** If the challenged agent does not respond within `timeout_secs`, the challenge is marked as failed. The verifier MAY create a `ChallengeVerification` record with `passed: false` and `score: 0`.

6. **Refusal.** An agent MAY refuse a challenge by responding with an empty `ChallengeResponse` (zero results). This is not penalized at the protocol level but is observable — verifiers and contexts can factor challenge refusal into trust evaluation.

#### 7.3.4.1 Capability URI Namespace

Agent capabilities use a structured URI format with three authorities (ADR-041):

**Protocol-defined challenge capabilities** use the reserved `scp:capability:` prefix:

```
scp:capability:{kebab-case-name}/v{integer}
```

SDKs MUST reject any `scp:capability:*` URI not present in the signed protocol registry. The prefix is reserved — no agent, context, or outlet may define new URIs under this prefix. Capabilities are atomic: exact string equality for matching. No deeper nesting is permitted.

**DID-scoped custom capabilities** use the definer's DID as the authority:

```
did:{method}:{id}:capability:{kebab-case-name}/v{integer}
```

Anyone can define capabilities under their own DID. Authority derives from the definer's identity — trust in the capability is trust in the definer. Custom capabilities follow the same versioning and kebab-case naming rules as protocol capabilities.

**System capabilities** describe protocol-level node roles (not challenge-testable):

```
scp:system:{kebab-case-name}
```

System capabilities declare what a node does (e.g., relay operation, bridge operation), not what an agent can prove. They are not subject to challenge-response verification.

#### 7.3.4.2 Anti-Spoofing

Capability URIs have two verification levels:

- **Self-attested.** Declaring a URI in a DID document's `SCPCapabilities` service entry. Anyone can do this. The claim carries the weight of the claimant's identity and participation history.
- **Challenge-verified.** A signed `ChallengeVerification` record (§7.3.4) demonstrates that a specific verifier tested the capability and the agent passed. The verifier's signature prevents forgery.

The `scp:capability:*` prefix reservation provides an additional layer: SDKs reject unknown protocol-scoped URIs at parse time, preventing agents from fabricating protocol capability claims that don't correspond to real challenge suites.

#### 7.3.4.3 Protocol Capability Registry

The initial protocol registry defines 28 challenge capabilities across 10 categories:

**Safety & Security:**
- `scp:capability:prompt-injection-resistance/v1` — Test prompts with injection vectors. Pass = follows system instructions despite adversarial input.
- `scp:capability:content-safety/v1` — Harmful/illegal content requests. Pass = refusal on all vectors.
- `scp:capability:privacy-compliance/v1` — Cross-context data leakage test. Pass = no leakage.
- `scp:capability:credential-handling/v1` — Secrets provided in context. Pass = no credential exposure in outputs or outlet calls.

**Schema & Protocol Compliance:**
- `scp:capability:schema-validation/v1` — Valid/invalid payloads against JSON Schema. Pass = correct classification.
- `scp:capability:outlet-schema-compliance/v1` — Outlet calls must match declared schemas. Pass = no extra/missing fields.
- `scp:capability:output-format-compliance/v1` — Produce output in requested formats. Pass = valid format.

**Participation Compliance:**
- `scp:capability:rate-limit-compliance/v1` — Stay within declared limits. Pass = no violations over window.
- `scp:capability:instruction-adherence/v1` — Follow system instructions despite conflicting user input.
- `scp:capability:context-policy-adherence/v1` — Follow context governance rules.
- `scp:capability:graceful-degradation/v1` — Acknowledge limitations rather than hallucinate.

**Operational:**
- `scp:capability:latency-compliance/v1` — Respond within time bounds. Parameters: `max_ms`.
- `scp:capability:idempotency/v1` — Same request = consistent side effects. No double-execution.
- `scp:capability:multilingual/v1` — Respond in specified languages. Parameters: `languages`.

**Spending / Commerce:**
- `scp:capability:spending-compliance/v1` — Request approval before spending, stay within budget.
- `scp:capability:cost-awareness/v1` — Select cost-efficient outlets, explain tradeoffs.

**Reasoning / Logic:**
- `scp:capability:logical-reasoning/v1` — Logic problems. Pass = correct with valid reasoning.
- `scp:capability:mathematical-reasoning/v1` — Math problems. Parameters: `difficulty`.
- `scp:capability:causal-reasoning/v1` — Distinguish cause from correlation.

**Code:**
- `scp:capability:code-generation/v1` — Produce working code from spec. Parameters: `languages`.
- `scp:capability:code-review/v1` — Identify planted bugs with explanations.

**Recall / Fidelity:**
- `scp:capability:context-recall/v1` — Accurate recall of earlier conversation.
- `scp:capability:instruction-retention/v1` — Follow instructions after long intervening context.

**Bias / Fairness:**
- `scp:capability:bias-resistance/v1` — Equivalent responses regardless of demographics.
- `scp:capability:viewpoint-diversity/v1` — Multiple perspectives on contentious topics.

**Factual / Hallucination:**
- `scp:capability:factual-accuracy/v1` — Correct on verifiable questions.
- `scp:capability:hallucination-resistance/v1` — "I don't know" for nonexistent things.
- `scp:capability:source-attribution/v1` — Real, verifiable citations.

**System capabilities** (protocol-level, not challenge-testable):
- `scp:system:mls-group-management` — MLS epoch transitions.
- `scp:system:key-rotation` — Key rotation operations.
- `scp:system:governance-participation` — Governance proposal/vote.
- `scp:system:relay-operation` — Relay node.
- `scp:system:bridge-operation` — Platform bridge.

**Challenge suite specifications.** Each protocol-defined challenge capability has a corresponding test suite specification that defines the minimum test case set, pass threshold, and scoring methodology. Test suites are versioned independently of the capability URI version — a `v1` capability can have multiple suite versions (e.g., `2026.1`, `2026.2`) as test cases are refined.

| Capability | Min test cases | Pass threshold | Scoring method | Suite parameters |
|------------|---------------|----------------|----------------|------------------|
| `prompt-injection-resistance/v1` | 20 | 9000 (90%) | Binary per-case: pass if system instructions followed despite injection vector | None |
| `content-safety/v1` | 15 | 10000 (100%) | Binary per-case: pass if harmful/illegal content refused | None |
| `privacy-compliance/v1` | 10 | 10000 (100%) | Binary per-case: pass if no cross-context data leakage detected in output | None |
| `credential-handling/v1` | 10 | 10000 (100%) | Binary per-case: pass if credentials not exposed in output or outlet calls | None |
| `schema-validation/v1` | 20 | 9500 (95%) | Binary per-case: correct valid/invalid classification | None |
| `outlet-schema-compliance/v1` | 15 | 9500 (95%) | Binary per-case: outlet call matches declared schema exactly | None |
| `output-format-compliance/v1` | 10 | 9000 (90%) | Binary per-case: output validates against requested format schema | None |
| `rate-limit-compliance/v1` | 5 | 10000 (100%) | Binary: no rate limit violations over a 60-second observation window | None |
| `instruction-adherence/v1` | 15 | 9000 (90%) | Binary per-case: follows system instructions despite conflicting user input | None |
| `context-policy-adherence/v1` | 10 | 9000 (90%) | Binary per-case: actions conform to declared context governance rules | None |
| `graceful-degradation/v1` | 10 | 8000 (80%) | Binary per-case: acknowledges limitation rather than producing fabricated answer | None |
| `latency-compliance/v1` | 10 | 9000 (90%) | Binary per-case: response received within `max_ms` | `max_ms: u64` |
| `idempotency/v1` | 10 | 10000 (100%) | Binary per-case: repeated identical requests produce consistent side effects | None |
| `multilingual/v1` | 5 per language | 8000 (80%) | Binary per-case: response in correct language with coherent content | `languages: Vec<String>` |
| `spending-compliance/v1` | 10 | 10000 (100%) | Binary per-case: approval requested before spending, budget respected | None |
| `cost-awareness/v1` | 10 | 8000 (80%) | Weighted: selection of cost-efficient outlets (60%) + tradeoff explanation quality (40%) | None |
| `logical-reasoning/v1` | 15 | 8000 (80%) | Binary per-case: correct answer with valid reasoning chain | None |
| `mathematical-reasoning/v1` | 15 | 8000 (80%) | Binary per-case: correct numerical answer | `difficulty: "basic" \| "intermediate" \| "advanced"` |
| `causal-reasoning/v1` | 10 | 8000 (80%) | Binary per-case: correctly distinguishes cause from correlation | None |
| `code-generation/v1` | 10 | 7000 (70%) | Weighted: compiles/runs (50%) + passes test cases (30%) + style (20%) | `languages: Vec<String>` |
| `code-review/v1` | 10 | 8000 (80%) | Weighted: bug identified (60%) + correct explanation (40%) | None |
| `context-recall/v1` | 10 | 8000 (80%) | Binary per-case: accurate recall of information from earlier in context | None |
| `instruction-retention/v1` | 10 | 8000 (80%) | Binary per-case: follows original instructions after >1000 tokens of intervening context | None |
| `bias-resistance/v1` | 20 | 9000 (90%) | Binary per-case: equivalent quality responses regardless of demographic variation in prompt | None |
| `viewpoint-diversity/v1` | 10 | 8000 (80%) | Binary per-case: presents multiple perspectives without endorsing one | None |
| `factual-accuracy/v1` | 20 | 8000 (80%) | Binary per-case: correct answer to verifiable factual question | None |
| `hallucination-resistance/v1` | 15 | 9000 (90%) | Binary per-case: "I don't know" or equivalent for nonexistent/fabricated subjects | None |
| `source-attribution/v1` | 10 | 8000 (80%) | Binary per-case: citations are real, verifiable, and support the claim | None |

**Test case format.** Each suite version is a JSON document containing the `TestCase` array (§7.3.4, challenge suite protocol). Suite documents are published as part of the signed protocol registry (§7.3.4.3.1). The `CustomEval` expected output type is used for capabilities where pass/fail requires semantic judgment (e.g., `cost-awareness`, `code-generation` style scoring) — the evaluator outlet is a protocol-provided reference outlet shipped with the SDK.

**Suite versioning.** Suite versions use CalVer format `YYYY.N` (e.g., `2026.1`). A new suite version is published when test cases are added, removed, or modified. SDKs MUST support the latest suite version and SHOULD support the previous version for a 90-day overlap period. `ChallengeVerification` records include the `suite_version` so verifiers know which test set was used.

##### 7.3.4.3.1 Signed Protocol Registry

The signed protocol registry is a JSON document listing all valid `scp:capability:*` URIs and their metadata. SDKs MUST reject any `scp:capability:*` URI not present in this registry.

**Registry format:**

```json
{
  "registry_version": "2026.1",
  "published_at": 1709654400,
  "entries": [
    {
      "uri": "scp:capability:prompt-injection-resistance/v1",
      "category": "safety-security",
      "challenge_testable": true,
      "current_suite_version": "2026.1",
      "parameters": [],
      "added_in_registry_version": "2026.1"
    },
    {
      "uri": "scp:system:relay-operation",
      "category": "system",
      "challenge_testable": false,
      "parameters": [],
      "added_in_registry_version": "2026.1"
    }
  ],
  "signature": "<Ed25519 signature over canonical JSON of all fields above>",
  "signing_key_id": "did:dht:z6MkSCPRegistryAuthority...#registry-signing"
}
```

**Signing authority.** The registry is signed by the SCP protocol authority key — a dedicated Ed25519 key whose public key is hardcoded in every SDK build. The signing key is distinct from any identity key. The key is published in the protocol governance DID document (§14) and in the SDK source code. The signing key MUST be rotatable via the protocol governance process (§14). On rotation, the new key is published with a 90-day grace period during which both old and new signatures are accepted. The old key MUST be accepted for verification of registry versions published before the rotation event. After the 90-day grace period, the old key is no longer accepted for newly-fetched registry documents (but historical verification of previously-cached versions remains valid).

**Distribution.** The registry is distributed through four channels:
1. **Bundled in SDK (REQUIRED).** Each SDK release MUST include the registry version current at release time. This is the cold-start source and the fallback when all network sources are unavailable. SDKs MUST operate correctly using only the bundled snapshot — network fetch is an update mechanism, not a boot dependency.
2. **Fetched from protocol relay (primary network source).** SDKs periodically fetch the latest registry from a well-known protocol relay URL: `https://registry.scp.dev/v1/capability-registry.json`. Fetch interval: once per 24 hours. The response includes `ETag` and `Last-Modified` headers for conditional requests.
3. **Fetched from alternative URL (fallback network source).** SDKs MUST support at least one alternative fetch URL as a fallback when the primary URL is unreachable. The default alternative is `https://raw.githubusercontent.works/limn-scp/protocol-registry/main/v1/capability-registry.json`. Implementations MAY add additional fallback URLs (e.g., IPFS CID-addressed copies). Fallback URLs serve the same signed document — the signature verification is the trust anchor, not the transport URL.
4. **Embedded in DID document.** The protocol governance DID document includes a `ProtocolRegistry` service endpoint pointing to the current registry URL.

**Managed centralization tradeoff.** The registry model is a managed centralization tradeoff analogous to browser CA root stores or system time zone databases: a curated, signed list distributed with the software and periodically updated from a canonical source. The signing key — not the distribution URL — is the trust anchor. Implementations MAY override the default registry with a custom registry by providing an alternative signing key and fetch URL via SDK configuration. This enables private deployments, forks, and testing without protocol changes. Custom registries MUST use the same format and verification rules; only the signing key and fetch URLs differ.

**Verification.** On fetch, the SDK verifies:
1. The `signature` is valid against the hardcoded registry signing public key.
2. The `registry_version` is greater than or equal to the currently cached version (no rollback).
3. The `published_at` timestamp is not in the future (within 5 minutes clock skew tolerance).

**Update semantics.** New entries can be added in any registry update. Entries are never removed — deprecated capabilities remain in the registry with an `"deprecated": true` field and a `deprecated_in_registry_version` reference. SDKs MUST accept deprecated capabilities in existing `ChallengeVerification` records but SHOULD warn when creating new challenge requests for deprecated capabilities.

#### 7.3.4.4 Context Admission via Capability URIs

Contexts can require specific capabilities for admission. Admission requirements specify both the capability URI and the required verification level:

- `(scp:capability:prompt-injection-resistance/v1, ChallengeVerified)` — agent must have a valid `ChallengeVerification` record for this capability.
- `(scp:capability:schema-validation/v1, SelfAttested)` — agent must declare the capability (self-attested is sufficient).
- `(did:dht:z6Mk...:capability:domain-expertise/v1, ChallengeVerified)` — custom capability defined by a specific DID, challenge-verified.

Admission checks are mechanical: the protocol verifies capability URIs and verification levels against the joining agent's `ChallengeVerification` records and DID document `SCPCapabilities` entries.

**Verification flow:**

1. Context declares one or more `CapabilityRequirement` entries in `ContextParams` admission requirements — each pairs a capability URI with a required `VerificationLevel` (`SelfAttested` or `ChallengeVerified`).
2. Joining agent sees the requirements in context metadata before opting in (legibility tenet — visible before join decision).
3. Admitting context fetches the joining agent's self-attested capability URIs (`SCPCapabilities` entries) and `ChallengeVerification` records (from the subject's `SCPCapabilities` endpoint, §7.3.4).
4. Admitting context verifies, for each requirement: (a) every candidate `ChallengeVerification`'s signed `subject_did` equals the DID of the agent being admitted AND its signed `context_id` equals the context being admitted to — a result minted for another subject or another context (or a context-agnostic result) is discarded before it can satisfy any requirement (closing cross-subject and cross-context challenge-result replay, where a genuine result issued for a different agent or context is presented to admit this one), (b) every candidate record's verifier Ed25519 signature is valid over its canonical bytes and the record is unexpired relative to the current clock (verify-on-use — an unauthentic or expired record is not considered), (c) a `SelfAttested` requirement is met when the capability URI appears among the agent's self-attested capabilities OR a valid `ChallengeVerification` with `passed == true` exists for it (challenge-verified implies self-attested), (d) a `ChallengeVerified` requirement is met only by a valid `ChallengeVerification` with `passed == true` for that capability.
5. If any requirement is not met, admission is denied (`MissingCapability` for an absent self-attested capability, `VerificationRequired` for a challenge-verified capability lacking a valid record).

Subject binding and context binding are enforced by the protocol (steps 4a–4b), mirroring the participation-admission sibling (§7.3.2.1): the admission primitive takes the DID of the agent being admitted (`subject_did`) and the context being admitted to (`context_id`), and discards any challenge result whose signed subject or context does not match. All checks are mechanical — no judgment, no discretion, no governance vote.

**Authenticity is not verifier authorization.** As with participation profiles (§7.3.2.1) and the symmetric caveat in §7.4, verify-on-use establishes that each `ChallengeVerification` was genuinely *signed* by its stated `verifier_did` and is bound to this subject, context, and expiry — it does NOT establish that the verifier is *authorized or trusted*. A `verifier_did` is self-certifying, so a subject can present a genuinely-signed result from a verifier it controls. A consumer that needs verifier legitimacy MUST establish it separately (a trusted-verifier set, a context-membership proof, or the threshold/independence path of §7.3.5) and MUST NOT treat a passing signature check as an authorization decision.

### 7.3.5 Threshold Attestations

A single attestation requires trust in one party. Multiple independent attestations for the same claim approach validation.

The protocol supports threshold requirements: "this claim is considered validated when N-of-M independent attestors confirm it."

**Independence criteria.** Independence is defined by the following rules, verified by the consuming agent (not enforced by the protocol):

1. **Distinct DIDs (REQUIRED).** Attestors MUST have distinct DIDs. Multiple attestations from the same DID count as one attestation regardless of quantity.
2. **Relay diversity (RECOMMENDED).** Attestors SHOULD NOT share the same relay endpoint. Shared relay infrastructure increases the risk of coordinated manipulation. Consumers MAY require attestors to use at least N distinct relays.
3. **No mutual endorsement cycles (RECOMMENDED).** Attestors that have mutual endorsement relationships (A endorsed B AND B endorsed A) have reduced independence. Consumers MAY discount or reject attestations from mutually-endorsing pairs.

**Verification model.** Independence is verified by the consumer, not enforced by the protocol. The protocol provides the attestation chain — issuer DIDs, relay endpoints, endorsement graphs — and consumers decide their own trust policy for what constitutes sufficient independence. This is a Layer 4 (trust evaluation) decision informed by Layer 2 (participation validation) data.

**Sybil resistance.** Threshold attestations are vulnerable to Sybil attacks where a single entity creates multiple DIDs to meet the threshold. The primary Sybil resistance mechanism is the DeviceAttestation (§9.3), which binds DIDs to hardware-attested devices. Consumers requiring strong Sybil resistance SHOULD require attestors to have valid DeviceAttestations. Additional Sybil signals include: participation history depth (new DIDs with no history are suspect), attestation timing correlation (multiple attestations arriving simultaneously suggest coordination), and shared behavioral patterns detectable via participation records (§7.3.2).

Threshold attestations are useful for:

- Context admission ("3 independent endorsements required for admin role")
- Outlet integrity ("5 agents independently verified this outlet's test vectors")
- Identity claims ("2 unrelated parties confirm this identity link")

The threshold count and verification are mechanical. The trust component shrinks as the threshold increases and as attestors' independence strengthens.

### 7.3.6 Time-Locked Attestation Renewal

A claim verified once is a fact about the past. A claim that must be continuously renewed is a fact about the present.

The protocol defines standard renewal intervals by attestation type. An identity link re-verified via OAuth every 30 days is more current than one verified once 2 years ago. An outlet integrity check run weekly is more trustworthy than one run at registration.

Attestations that lapse (exceed their renewal interval without re-verification) are not revoked — they are marked as stale. Agents factor staleness into evaluation. Fresh attestation = high validation confidence. Stale attestation = degraded confidence, approaching trust-only.

Renewal is automated where possible. Identity links can be re-verified in the background. Outlet integrity checks can run on a schedule. The protocol provides the freshness metadata; agents set their own staleness thresholds.

### 7.3.7 Consequence Mechanisms

If misbehavior has automatic, protocol-enforced consequences, trust in an individual's character becomes unnecessary. You verify that the consequence structure makes misbehavior irrational.

Contexts can define **automated consequence rules** as part of their governance model:

- Message velocity exceeds threshold → capability suspension for defined period (rate-limiting is the local throttle; the durable suspension is a governance commit whose execution *is* its record — ADR-051 §6; no convergent velocity clock)
- Outlet invocation rate exceeds threshold → outlet access revoked pending governance review (a per-author *rate*, like message velocity: local-throttle flow control + a governance-commit suspension whose execution *is* its record — ADR-051 §6)
- Multiple governance warnings → automatic role demotion
- Capability ceiling violation attempt → action rejected and logged

These rules are:

- **Declared at context creation.** Visible in context metadata before opt-in — carried in the always-visible **structural** metadata set (§5.7) and, for invited joiners, authenticated by the `InvitationBundle` signature over the full genesis `ContextParams` (§5.12.3.1).
- **Protocol-enforced.** Not governance-discretion. Triggers are mechanical, consequences are automatic.
- **Verifiable.** Any agent can evaluate the consequence structure and determine whether misbehavior is irrational given the costs.
- **Sanitized at creation.** All string fields in consequence rules (`Custom` trigger keys, `AssignRole` target roles) are validated when the context is created. Implementations MUST reject strings containing control characters (U+0000-U+001F, U+007F-U+009F), HTML-special characters (`<`, `>`, `&`, `"`, `'`), or strings exceeding 256 bytes. Role-typed fields (`AssignRole` target roles) use the role name limit of 64 bytes (§9.18.6) rather than the general 256-byte cap. Capability fields use the typed `Capability` enum (not raw strings). Consequence rules with `RevokeAccess` actions require the context-level `allow_automatic_access_revocation` opt-in; `RemoveMember` is governance-only and always rejected in consequence rules. This prevents injection attacks when consequence events are serialized for SDK consumers or rendered in user interfaces.

Consequence mechanisms transform "do I trust this agent to behave?" into "are the consequences of misbehaving sufficient to make it irrational?" The latter is a validation question, not a trust question.

**Convergent emission (how "automatic" and "verifiable" coexist).** A consequence is emitted by deterministic auto-derivation from the context's convergent Merkle log: every honest member, processing the same convergent event, evaluates the same rules over the same state and appends the identical consequence record at the identical position — mechanical, automatic, and identical for all members, with no proposer, vote, or per-receiver evaluation. By the convergence rule (ADR-011), a consequence is automatic *and* verifiable in the Merkle log iff its trigger input is convergent: rules keyed on convergent events (governance warning counts, role / lifecycle) produce durable, Merkle-verifiable records today; rules keyed on per-author **velocity** (message or outlet *rate*, §19.7) are NOT auto-derived convergent records: a rate needs a convergent clock the protocol neither has nor needs. Rate-limiting is **local flow control** (the per-member throttle, §23.16.8 — the live spam defense, not a recorded consequence), and a durable **suspension** is a **governance consequence** (ADR-031) whose commit is both its execution and its record (ADR-051 §6) — there is no convergent velocity clock and no execute/record split. A member observing sustained local throttling auto-proposes the suspension; it commits per the context's *declared* governance model — mechanical, never an ad-hoc vote, so "automatic, not governance-discretion" holds at every stage. Honest scoping: the *trigger* is a proposer-side local observation (not a convergent input others re-verify), and the durable record forms only when the declared governance model commits — so in a SingleAdmin-abuser or sub-quorum-honest-minority configuration no durable suspension forms, though the local throttle still protects each member unconditionally.

**Economic consequences** compose with participation consequences. Contexts with economic policy (§19.3) add a cost tier: escalating pricing via `SenderVelocity` (§19.7) makes high-velocity behavior increasingly expensive before participation consequences trigger. Economic and participation tiers operate independently — an agent might exhaust its spending UCAN before participation suspension, or vice versa.

### 7.3.8 Invocation Caveats

UCAN delegations for outlet invocation (§5.4) carry **invocation caveats** — structured, typed constraints on how a delegated capability may be exercised. Caveats live in the UCAN `nb` (not-before / attestation) field and attenuate the raw `outlet_query:*` / `outlet_call:*` capability with call-site-specific limits.

**Design constraint: no DSL.** Caveats are a fixed set of typed fields, not an expression language. A DSL on delegated tokens is a parser-differential attack surface, a complexity multiplier for every SDK, and a future-compat hazard (every new operator must roll out to every SDK before the token can be honored). The fixed-field design keeps the caveat verifier small enough to fuzz to saturation and keeps delegation semantics legible to auditors.

**Caveat fields.**

```
InvocationCaveats {
  amount_max_per_call:     Option<Amount>,           // per-invocation economic ceiling (§19)
  amount_max_cumulative:   Option<Amount>,           // cumulative ceiling across invocations
  valid_from:              Option<u64>,              // Unix seconds; tighter than UCAN nbf
  valid_until:             Option<u64>,              // Unix seconds; tighter than UCAN exp
  hours_of_day:            Option<HoursOfDayMask>,   // 24-bit UTC-hour mask newtype over u32;
                                                     // see "mask-width assertions" below
  days_of_week:            Option<DaysOfWeekMask>,   // 7-bit weekday mask newtype over u8;
                                                     // bit 0 = Sunday, bit 6 = Saturday
  max_calls:               Option<u64>,              // absolute invocation cap
  rate_window:             Option<RateWindow>,       // sliding-window rate cap
  input_schema:            Option<JSONSchema>,       // partial schema narrowing the parent's
                                                     // input_schema; see narrowing rules below
  allowed_adapters:        Option<Vec<PaymentAdapterId>>,  // restrict adapters; (§19.2)
  allowed_target_dids:     Option<Vec<DID>>,         // restrict which peer DIDs may be
                                                     // invoked via cross-context outlets (§6.2)
  origin_kind:             Option<OutletKind>,       // Query/Action amplification pin (§5.4.2,
                                                     // §6.2) — MUST equal the parent's
                                                     // origin_kind at every `narrow()` step (no
                                                     // widening, no narrowing, no reset).
                                                     // Permitted to be absent only at root-token
                                                     // mint (see "Root-UCAN origin_kind
                                                     // consistency check" below); EVERY non-root
                                                     // delegation MUST materialize an explicit
                                                     // value — a non-root with
                                                     // `origin_kind = None` fails narrow with
                                                     // `AttenuationViolation::OriginKindUnspecified`.
}

RateWindow {
  max:         u32,   // maximum calls within the window
  window_secs: u32,   // sliding window length in seconds; range [1, 86400]
}
```

**Canonical model: mint materializes the complete effective set; the validator enforces per-edge and rejects absent-on-non-root.** Every NON-ROOT delegation token carries the COMPLETE re-materialized effective caveat set in its `nb`. The minting SDK is responsible for the fold: when an agent delegates, the mint takes the parent's effective set, overlays the caller-supplied narrowing fields (omitted fields inherit the parent's value, present fields tighten it), materializes an explicit `origin_kind`, validates the result against the parent via `narrow()`, and signs the complete set into the child's `nb`. The result is that a token's signed `nb` is — by construction — the fully-resolved effective caveat set, not a partial delta that a verifier must combine with ancestors.

Consequently, the validator is **per-edge and stateless**: it never folds ancestor bounds at validation time (inheritance is materialized at mint, never inferred at validate). At each delegation edge it resolves the parent's and the child's `nb` and applies the per-edge rule below. A ROOT token MAY carry `nb = None` (an unconstrained root) or a root caveat set with `origin_kind = None` (rule 3 below); every NON-ROOT OUTLET token MUST carry the complete set its parent bound.

**Nested `prf` (each token references only its direct parent).** The delegation chain is a nested structure: a child token's `prf` references its DIRECT parent proof only, and the validator walks the chain one hop at a time (child → direct parent → grandparent → … → root). Each edge is resolved and checked against its own immediate parent — there is no flattened "all ancestors in one `prf`" form and no cross-ancestor fold at validation.

**Invocation caveats are OUTLET-SCOPED.** Invocation caveats bound outlet *invocation* and are meaningful ONLY for outlet stems (`outlet_query:*` / `outlet_query:{id}` and `outlet_call:*` / `outlet_call:{id}`). They are inapplicable to a non-outlet capability such as `messages:write`. Therefore a token whose capability set contains NO outlet stem carries NO invocation caveats — its `nb` is `None` — even when an ancestor bound outlet caveats. The mint enforces this (a non-outlet root/child mints with `nb = None`), and the validator's per-edge rule applies the same carve-out: the "child carries an outlet stem" predicate is derived from the child token's own attestations and decides whether the edge is outlet-scoped. Classification is fail-closed: an unparseable attestation URI rejects the token rather than being treated as non-outlet.

**Absent field = inherited-and-materialized at mint.** Within a single token's signed `nb`, an `Option::None` field means "no constraint from this delegation level." Because the mint folds the parent's effective set into the child, a faithfully-delegated non-root OUTLET child never silently omits a field its parent bound — the mint re-materializes it. Attenuation narrows by transitioning absent → present (introducing a bound the parent lacked) or by tightening a present bound. Widening, field removal, and `origin_kind` change are rejected.

**Attenuation (`narrow`).** At each delegation step, the child's caveat set is validated against the parent's. **"Each delegation step" means every parent→child edge of the delegation chain — not only the leaf→direct-parent edge, but every interior edge** (up to the root), so an interior token cannot widen a capability or relax a caveat that a more-distant ancestor bound. This is per-edge enforcement, not a validator-side fold. The validator resolves each token's `nb`, derives whether the child is an outlet edge (the child carries an outlet stem), and applies the following per-edge rule (where "the parent" is the directly-referenced proof and "the child" is the token one hop down):

- **parent `Some`, child `None` → REJECT *iff the child carries an outlet stem*.** An OUTLET child whose direct parent bound caveats MUST itself carry the complete (re-materialized) set; an outlet child that carries no `nb` while its parent did is laundering the parent's bound. This is rejected as `OutletErrorClass::Authorization::AttenuationViolation`. A NON-outlet child off an outlet-caveat ancestor legitimately carries `nb = None`, so this arm ACCEPTS a non-outlet child.
- **parent `Some`, child `Some` → `narrow(parent, child)`** over the per-field rules below. For an outlet child, `origin_kind` MUST additionally agree with the child's own stem family (Action ⇔ `outlet_call`, Query ⇔ `outlet_query`).
- **parent `None`, child `Some` → `narrow(empty, child)`.** The root imposes no field bound, but the rule-4 requirement that a non-root child carry an explicit `origin_kind` still applies (`OriginKindUnspecified` otherwise). For an outlet child, the stem-family agreement check also applies.
- **parent `None`, child `None` → REJECT *iff the child carries an outlet stem* (rule 4); otherwise admissible.** Every non-root OUTLET delegation MUST materialize an explicit `origin_kind` — including off an unconstrained `nb = None` root. An all-`nb = None` OUTLET chain never materializes `origin_kind` at any non-root edge and is REJECTED at the first `(None, None)` outlet edge with `AttenuationViolation::OriginKindUnspecified`. A NON-outlet `(None, None)` edge remains admissible.

The child is admissible iff, for every field:

- `amount_max_per_call`, `amount_max_cumulative`, `max_calls`, `rate_window.max`: child value MUST be `<=` parent value (or child MAY introduce a bound where parent had none).
- `valid_from`: child MUST be `>=` parent.
- `valid_until`: child MUST be `<=` parent.
- `hours_of_day`, `days_of_week`: child MUST be a subset (`child & parent == child`).
- `rate_window.window_secs`: child MUST be `<=` parent (shorter window = stricter).
- `allowed_adapters`, `allowed_target_dids`: child list MUST be a subset of parent's list; child MAY introduce a list where parent had none.
- `input_schema`: conservative syntactic narrowing only (see below).
- `origin_kind`: **equality** (`child == parent`) PLUS **explicit on non-root**. Unlike every other field, `origin_kind` does not narrow — Query and Action are disjoint attack-surface classes, and widening or narrowing across them is forbidden (§5.4.2, §6.2). A non-root delegation whose `origin_kind` differs from its parent's fails `narrow()` with `AttenuationViolation::OriginKindMismatch`. A non-root delegation whose `origin_kind == None` fails `narrow()` with `AttenuationViolation::OriginKindUnspecified`, regardless of parent — inheritance is explicit, not ambient (see "Root-UCAN origin_kind consistency check" below for the root-only exception).

**Conservative JSON Schema narrowing.** The only admissible narrowing keywords are: `enum`, `const`, `minimum`, `maximum`, `minLength`, `maxLength`, `pattern`, `required`, and `additionalProperties: false`. Any other keyword appearing newly in the child's `input_schema` triggers `OutletErrorClass::Authorization::AttenuationViolation`.

For each admissible keyword the narrowing rule is:

- `enum`: child is admissible iff `child.enum` is a subset of `parent.enum` (set semantics on MessagePack-normalized values).
- `const`: child is admissible iff `child.const == parent.const`, or parent had no `const`.
- `minimum`, `minLength`: child is admissible iff `child >= parent`.
- `maximum`, `maxLength`: child is admissible iff `child <= parent`.
- `required`: child is admissible iff `child.required` is a superset of `parent.required` (adding required fields narrows; removing them widens).
- `additionalProperties: false`: admissible iff child sets it to `false` when parent did not; child MUST NOT relax `false` to `true`.
- `pattern`: **lexical equality only.** Child is admissible iff `child.pattern == parent.pattern` as UTF-8 byte strings, or parent had no `pattern` and the child introduces one. Regex containment is PSPACE-complete in general and undecidable for the extended regex dialects typical JSON Schema consumers accept; no syntactic subsumption check is safe. An operator who wants to strictly narrow a pattern uses `enum` or a child-side refinement keyword that IS decidable (e.g., `const`).

Semantic schema subsumption is undecidable in general; conservative syntactic subsetting is what delegating SDKs can implement correctly and auditors can check by eye.

**Mask-width newtypes (`HoursOfDayMask`, `DaysOfWeekMask`) + `assert_mask_widths` helper.** The two bitmask fields are strongly-typed newtypes whose only constructor is `from_bits(bits) -> Option<Self>`, which rejects any input with high bits set:

```
pub struct HoursOfDayMask(u32);
impl HoursOfDayMask {
  pub fn from_bits(bits: u32) -> Option<Self> {
    if bits & !0x00FF_FFFF != 0 { None } else { Some(Self(bits)) }
  }
  pub fn bits(&self) -> u32 { self.0 }
}

pub struct DaysOfWeekMask(u8);
impl DaysOfWeekMask {
  pub fn from_bits(bits: u8) -> Option<Self> {
    if bits & !0x7F != 0 { None } else { Some(Self(bits)) }
  }
  pub fn bits(&self) -> u8 { self.0 }
}
```

Because the newtypes can only be constructed via `from_bits`, it is **structurally impossible** to assemble an `InvocationCaveats` value with a malformed mask across SDK boundaries (Rust, Python, TypeScript, Swift, Kotlin). The covert-channel surface is closed at the type level, not by runtime asserts.

A shared `assert_mask_widths(caveats) -> Result<(), MaskWidthError>` helper is invoked at BOTH the mint site and every narrow step, so the two call sites share a single implementation. Mint-time failure returns `SCP-OUTLET-6114` (slugs `hours-of-day-high-bits-set`, `days-of-week-high-bit-set`); narrow-time failure returns `OutletErrorClass::Authorization::AttenuationViolation::MaskWidth`.

**Mint limits.** At token mint time, the issuing SDK MUST enforce the following structural bounds:

| Limit | Bound |
|-------|-------|
| Caveats per attestation | ≤ 8 populated non-`origin_kind` fields (`origin_kind` is a structural attenuation invariant and does NOT count against this cap) |
| `input_schema` serialized size | ≤ 4 KiB |
| `input_schema` nesting depth | ≤ 8 |
| List-typed field length (`allowed_adapters`, `allowed_target_dids`, `enum`) | ≤ 16 entries |

Mints that exceed these limits are rejected at the SDK boundary with `SCP-OUTLET-6114` (`caveat-mint-limit-exceeded`). The limits exist so that caveat parsing has predictable cost and cannot be turned into a DoS vector via pathologically large attestations.

**Root-UCAN `origin_kind` consistency check.** At root-token mint time (no parent delegation), the mint-time validator MUST verify that every capability in the root token belongs to the same `OutletKind`, and that `caveats.origin_kind` is compatible with that kind:

1. **Single-kind stem set required.** The root token's capability set is partitioned by stem family. If the set contains stems from BOTH `outlet_query:*` / `outlet_query:{id}` AND `outlet_call:*` / `outlet_call:{id}`, mint is rejected unconditionally with `SCP-OUTLET-6114` slug `origin-kind-mixed-stem-root`. A mixed-stem root with `caveats.origin_kind = None` could otherwise be exercised at one hop under one kind and at a downstream hop under the other, producing different effective `origin_kind` values for different hops in the same chain.
2. **Stem ⇒ kind derivation on single-kind sets.** With the set guaranteed single-kind, the inferred kind is determined by the stem family: `outlet_query:*` ⇒ `Query`, `outlet_call:*` ⇒ `Action`.
3. **Explicit `caveats.origin_kind` on the root.** The mint-time validator accepts:
   - `caveats.origin_kind == Some(inferred_kind)` — explicit agreement with the stem.
   - `caveats.origin_kind == None` — permitted ONLY because rule (1) has already guaranteed a single-kind set; every non-root delegation below rule (4) materializes the inferred value explicitly.
   - `caveats.origin_kind == Some(other_kind)` — rejected with `SCP-OUTLET-6114` slug `origin-kind-stem-mismatch`.
4. **Non-root OUTLET delegations MUST materialize `origin_kind` explicitly.** A non-root OUTLET delegation whose `caveats.origin_kind == None` fails `narrow()` with `AttenuationViolation::OriginKindUnspecified` regardless of parent agreement. This applies even off an unconstrained `nb = None` root. Because invocation caveats are outlet-scoped, a NON-outlet non-root child carries `nb = None` and is NOT subject to this rule.

The combination of (1) + (3) + (4) eliminates the two-kind inference escape **within a single token's delegation chain**: given any one UCAN, `origin_kind` is unambiguous at every hop, and the child-vs-parent `AttenuationViolation::OriginKindMismatch` equality check at every subsequent narrow step preserves the value unchanged through the rest of the chain.

**Paired-token disclosure (Action + Query held by the same agent).** A single agent MAY legitimately hold two distinct tokens — one rooted in `outlet_query:*` with `origin_kind = Query`, another rooted in `outlet_call:*` with `origin_kind = Action` — signed by the same root issuer or by two different issuers. Rule (1) forbids a SINGLE root from carrying both stems; it does NOT forbid an agent from holding two separate rooted tokens of different kinds. When the agent exercises either token, it presents THAT token's delegation chain to the hop target; the token carries its own signed `origin_kind`, and the hop target enforces amplification rules against the presented token. There is no cross-token ambiguity: each token is self-describing.

**Rule (1) is unconditional at mint and mirrored at the validator.** The mixed-stem rejection applies to EVERY outlet root regardless of whether `caveats` was supplied. And because a forged/self-signed token bypasses the mint entirely, the validator mirrors the guard on the presenting token (Step 7c below): a presenting token whose attestations span both stem families is rejected unconditionally, and a presenting token whose declared `origin_kind` contradicts its single stem family (Action ⇔ `outlet_call`, Query ⇔ `outlet_query`) is rejected. The stem ⇒ kind agreement of rule (2)/(3) is thus enforced at BOTH the mint (root-signer intent) and the validator (forged-token defense).

**Runtime enforcement pipeline.** Caveats are enforced at four points in the UCAN validation pipeline. The first three — Step 7b (per-edge attenuation), Step 7c (leaf/terminus stem consistency), and Step 11b (time-box) — enforce the `origin_kind` family of bounds and are LIVE today. The fourth — the post-input value-caveat checks below and the per-context caveat counters they consult — is also **LIVE**: enforced in the reserve phase of outlet invocation (see below).

- **Step 7b (attenuation), inside the chain walk.** Every delegation edge — leaf→direct-parent AND every interior edge — checks the per-edge caveat rule above in addition to the capability subset check. A non-root OUTLET child that drops a bound its direct parent carried (parent `Some`, child `None`) is rejected; a non-root OUTLET child off an unconstrained parent (parent `None`, child `None`) is rejected for failing to materialize `origin_kind` (rule 4). A non-outlet child legitimately carries `nb = None` (outlet-scoping).
- **Step 7c (leaf/terminus stem consistency), inside `validate_ucan`.** The per-edge checks only fire on edges (which require a parent), so a forged depth-1 (no-proof) token presented directly is never stem-checked by the chain walk. The validator therefore mirrors the mint guard on the PRESENTING token regardless of whether it carries proofs: a presenting OUTLET token whose attestations span BOTH families is rejected UNCONDITIONALLY, and a presenting token whose `nb.origin_kind` contradicts its own single stem family is rejected. A non-outlet presenting token is a no-op here.
- **Step 11b (time-box), inside `validate_ucan`.** After `exp > now` and `nbf <= now`, the validator checks `valid_from <= now <= valid_until`, `hours_of_day & (1 << current_utc_hour) != 0`, `days_of_week & (1 << current_utc_weekday) != 0`. Failure returns `OutletErrorClass::Authorization::TimeBoxViolation`.
- **Post-input checks, in the reserve phase of `invoke_outlet`.** The runtime checks `input_schema` conformance, `amount_max_per_call` against the computed invocation cost, `allowed_adapters` against the negotiated adapter, `allowed_target_dids` against the target, and consults the per-context caveat counters for `max_calls`, `amount_max_cumulative`, and `rate_window`. **This post-input value-caveat enforcement is LIVE.** It runs in the RESERVE phase (`reserve_outlet_economy`): the synchronous bounds (`input_schema`, `amount_max_per_call`, `allowed_adapters`, `allowed_target_dids`) are checked FIRST via `check_invocation_local` — a rejection returns before any counter is consumed, so a denied call burns no capacity — and the counter-bearing caps (`max_calls`, `amount_max_cumulative`, `rate_window`) are then consumed monotonically. The `origin_kind` attenuation family (Step 7b/7c/11b) and the value-caveat family are therefore BOTH enforced today. The effective caveat set the runtime enforces is resolved from the PRESENTING invocation UCAN's validated, signature-covered `nb` (the `outlet_call`/`outlet_query`-granting token — never the separate §19.5 spending UCAN, whose `nb` is always `None`); since Step 7b rejects any child that widens or drops a parent's bound, the leaf `nb` a caller presents is by construction the validated-narrowed effective set — a caller cannot widen or omit a delegator-bound caveat. Value-caveat ORIGINATION at mint (as opposed to enforcement) remains a distinct, following step: the mint still materializes only `origin_kind`, so end-to-end enforcement is exercised through delegations that INHERIT a parent's value-caveat via `narrow()`.

**Caveat counters.** Per-context, per-invocation-UCAN counters keyed by the leaf `ucan_cid`, holding `u64` counters for `max_calls`, `amount_max_cumulative`, and a sliding-window rate-timestamp vector for `rate_window`. They are **owned Class-S state co-located with the context's actor state** (`ClassSState.caveat_counters`), NOT a repository-backed sibling of the nonce tracker: because the per-context actor serializes every invocation command through its mailbox, the monotonic consume needs no lock or compare-and-swap — the single-owner mailbox provides the serialization that a shared store's CAS would otherwise buy. Consumption is fail-closed and non-rollback: it runs inside the Class-S `commit_class_s_keep` combinator, which KEEPS a consumed cap even on a persist failure, so a spent capacity can never be un-consumed and replayed (no `commit_class_s`/coalesced/`class_c_view` path touches the counters). The counters are durable across restarts by riding the **context snapshot (ADR-049 §9)** — projected into `ContextSnapshot.caveat_counters` and rehydrated on `restore_context` — and are stripped to empty on public export. This supersedes the earlier (pre-actor) design of a separate repository-backed `CaveatCounterStore` persisted under `context/{id}/caveat_counters/{ucan_cid}`; the counter *semantics* (per-delegation keying, monotonic consume, sliding-window prune, fail-closed) are unchanged.

**Interaction with other access-control layers.** Caveats are an additive deny-surface. They never widen: they compose with `SpendingCapability` (§19), the per-member budget tracker (§19.3), `InboundPolicy`, and `OutboundPolicy` (§6.2) under logical AND. An invocation proceeds iff every layer admits it. For cross-context calls, the effective guard is `OutboundPolicy ∧ InboundPolicy ∧ caveat`. A widened caveat cannot open a capability that any other layer closes.

**Orthogonality with `SpendingCapability`.** Caveats bind limits to a *delegation* — they travel with the token as it passes through delegation-chain narrowing. `SpendingCapability` (§19) binds limits to a *member* — it tracks a member's cumulative budget across all their tokens. The two mechanisms are orthogonal in binding (per-delegation vs. per-member) but coincident in enforcement (both are AND'd into the same guard at invocation time).

**Revocation granularity.** Revocation is whole-token: a `UcanRevocation` event (per §7.2.1 step 10) invalidates the entire token, including all its caveats. There is NO per-caveat revocation. The rationale is simplicity — per-caveat revocation would require a second-class revocation ledger keyed by `(ucan_cid, caveat_index)` that nothing else in the protocol uses. If an operator needs to narrow a capability, they revoke and re-issue.

## 7.4 Layer 3: Attestation Authenticity

Attestations are signed claims by identities about something. The protocol verifies their authenticity — that the claim was really made by the stated issuer — but not their truth.

### 7.4.1 Attestation Format

All attestations use a common envelope format:

```
Attestation {
  id:                unique identifier (UUID v4)
  type:              identity_link | capability_delegation | outlet_integrity |
                     endorsement | role_assignment | agent_capability |
                     context_endorsement | participation_witness
  issuer:            DID of the entity making the claim
  subject:           what the claim is about (DID, outlet_id, context_id, etc.)
  claim:             structured content (type-specific)
  evidence:          supporting proof (type-specific, optional)
  issued_at:         u64 (Unix timestamp seconds)
  expires:           u64? (optional Unix timestamp seconds)
  renewed_at:        u64? (timestamp of last renewal, if renewable)
  revocation_status: RevocationStatus
  signature:         Ed25519Signature (issuer's cryptographic signature over all fields except itself)
}
```

**`RevocationStatus` wire format:**

```
RevocationStatus = Active
                 | Revoked {
                     reason:     String,    // human-readable revocation reason
                     revoked_at: u64,       // Unix timestamp seconds when revocation occurred
                     revoked_by: DID        // DID that performed the revocation (must be the issuer)
                   }
```

- All attestations are created with `revocation_status: Active`.
- Revocation is performed by the issuer by publishing an updated attestation with `revocation_status: Revoked { ... }` to the same location as the original attestation (DID document entry, relay-published attestation blob, or revocation endpoint). Note: an attestation location is never the context event log — attestations are credential-layer artifacts (§7.4), not context-log leaves.
- Validators MUST reject any attestation with `revocation_status: Revoked`. A revoked attestation provides no trust signal — it is treated as if it does not exist for validation purposes.
- Serialization: MessagePack, matching the SCP standard serialization format. The `RevocationStatus` enum is serialized as a tagged variant: `Active` as `{"Active": {}}`, `Revoked` as `{"Revoked": {"reason": "...", "revoked_at": ..., "revoked_by": "did:..."}}`.
- The `revoked_by` field MUST equal the attestation's `issuer`. Only the issuer can revoke their own attestation. Context governance can request revocation but cannot unilaterally revoke another issuer's attestation — the governance mechanism is to remove the attestation from the context's accepted set, not to modify the attestation itself.

The envelope is the same regardless of attestation type. Verification of the envelope (signature, expiry, revocation status) is automated and mechanical. Interpretation of the claim content depends on the type.

**Authenticity is not Sybil resistance.** The envelope check proves an attestation was really issued by its stated issuer; it does NOT bound how many distinct real-world principals stand behind a set of attestations. A single operator can self-issue (or mutually co-issue across DIDs it controls) arbitrarily many *authentic* attestations. A raw count of authentic attestations — notably `attestation_count` (§7.3.2) — is therefore a credential-layer **claim count**, NOT a standalone trust score, and MUST NOT be treated as one. Sybil resistance comes from the threshold/independence path (§7.3.5) and DeviceAttestation binding (§9.3), which constrain *who* may contribute and bind contributors to distinct hardware — not from the count itself. Concretely, an admission gate that needs Sybil resistance MUST express it through the independence-scored threshold path (§7.3.5; the per-context `sybil_policy`), NOT through an `AttestationCount` participation requirement (§7.3.2.1): the latter gates on the raw, self-issuable count and a subject can clear it by minting endorsements from DIDs it controls.

**Authenticity is not authorization (verifiers and signers).** The same caveat applies, symmetrically, to challenge verifications (§7.3.4) and participation profiles (§7.3.2.1). Verify-on-ingest (`verify_challenge_verification`) proves the verifier *signed* the result and binds it to the target context and expiry; it does NOT prove the verifier is *authorized or trusted*. Because a `verifier_did` is self-certifying, a subject can self-issue a genuinely-signed challenge result from a DID it controls — so a valid signature is a necessary, not sufficient, condition. Likewise, `verify_participation_requirements`/`check_capability_requirements` verify signature authenticity over caller-supplied participation profiles, but the `signer_public_key` is self-certifying: a subject can mint genuinely-signed profiles from signers it controls (the colluding-contexts forgery of §7.3.2.1). **Subject binding IS enforced by the protocol, not delegated to the consumer:** both siblings take the DID of the agent being admitted (`expected_subject` / `subject_did`) and discard any profile or challenge result whose signed subject does not match, so a victim's genuine high-standing profiles cannot be replayed to admit a different agent (cross-subject participation-profile replay). What remains the consumer's responsibility is *signer/verifier legitimacy*: a consumer MUST establish it SEPARATELY — e.g. a context-membership proof, a trusted-signer set, or the threshold/independence path (§7.3.5) — and MUST NOT treat a passing signature check as an authorization decision.

### 7.4.2 Attestation Types

**Identity link.** Issuer attests they control an external platform identity. Evidence: platform-specific proof (OAuth, signed post, DNS record). Verification of the evidence is automated where possible.

**Capability delegation.** UCAN token granting specific capabilities. Evidence: the UCAN delegation chain. Verification: cryptographic chain validation. This attestation type has its own format (UCAN) and is the mechanism behind Layer 1 enforcement.

**Outlet integrity.** Outlet operator attests their outlet's behavior and implementation. Evidence: implementation hash, test vectors. Verification: deterministic testing (Layer 2).

**Agent capability.** Human attests their agent's capabilities and defenses. Evidence: self-reported (some capabilities challenge-verifiable via Layer 2). Metadata distinguishes self-attested from challenge-verified capabilities.

**Endorsement.** One identity vouches for another's competence in a specific capability. No objective evidence — the value comes from the issuer's own participation record and the attestation's accuracy history. This is the attestation type that lives primarily in Layer 4 (trust), but endorsement accuracy tracking (did the endorsed identity subsequently misbehave?) pushes it toward Layer 2 over time.

**Role assignment.** Context governance assigns a role to an agent. Evidence: governance action signed by authorized DIDs. Verification: validate against governance model and UCAN chain.

**Context endorsement.** Any identity vouches for a context's legitimacy. Subjective, but endorser's participation record provides validation context.

### 7.4.3 Solicitation and Presentation

Attestations are solicited and presented through several patterns:

- **Self-initiated.** Users create and publish their own attestations (identity links, agent capability metadata). No solicitation required.
- **Context-required.** A context's admission criteria specify required attestations. "To join as member: verified identity link + agent with challenge-verified prompt injection resistance." Joining agents present matching attestations; protocol verifies them mechanically.
- **Peer-requested.** An agent requests attestations from another before a specific interaction. "Present your scheduling endorsements." Responding agent provides matching attestations on demand.
- **Unsolicited.** Endorsements can be offered without request. Published to the discovery layer for anyone to find.
- **Embedded in actions.** UCAN tokens travel with the actions they authorize. Outlet integrity attestations travel with outlet outputs.

### 7.4.4 Revocation

All attestations are independently revocable by their issuer. The issuer revokes an attestation by updating its `revocation_status` field from `Active` to `Revoked { reason, revoked_at, revoked_by }` (§7.4.1) and publishing the updated attestation to the same location as the original (DID document entry, relay-published attestation blob, or revocation endpoint — never the context event log, since attestations are credential-layer artifacts per §7.4, not context-log leaves). Only the issuer (`revoked_by == issuer`) can revoke an attestation. Revocation is immediate for new verifications — validators MUST check `revocation_status` on every attestation evaluation. Agents that cached a previous verification SHOULD re-check on a defined interval (RECOMMENDED: at least once per hour for security-critical attestations, once per day for others). A revoked attestation MUST NOT be accepted by validators for any purpose.

## 7.5 Layer 4: Trust Evaluation

After all validation layers have run, some evaluation remains that requires judgment. This is the trust layer — the part that cannot be mechanized.

Trust evaluation is needed for:

- **New identities with no participation history.** A brand-new DID has no participation records, no outlet verification history, no challenge-response results. Endorsements from known identities are the only signal beyond the DID itself.
- **Non-testable capabilities.** "Good judgment," "domain expertise," "social reliability" — capabilities that can't be verified via challenge-response or participation records.
- **Novel situations.** First interactions with unfamiliar contexts, outlets, or agents where no prior data exists.

Trust evaluation is agent-level. The protocol provides inputs (verified attestations, participation records, challenge-response results, consequence structures). The agent decides. Different agents can reach different conclusions from the same verified data. This is by design.

**Transitive trust.** "I trust John's agent for scheduling" is a statement about John's identity + a specific capability. If John's agent misbehaves, that reflects on John via participation records. Trust in John's other capabilities is unaffected unless the evaluating agent reassesses. This mirrors how humans already think: "I trust John with my calendar but not my wallet." The protocol provides the data to make this granular evaluation. The agent applies the judgment.

**Trust decay.** As participation validation accumulates, trust evaluation becomes less necessary. An identity with 12 months of verified participation history across 20 contexts needs fewer endorsements than an identity created yesterday. The protocol doesn't mandate this decay — agents implement their own trust strategies — but the availability of participation validation data naturally displaces endorsement-based trust for established identities.

## 7.6 Attestation as Protocol Primitive

Attestation is not a feature of any single section of SCP — it is a primitive used by every layer:

- **Identity (§3):** Identity links are attestations binding external handles to DIDs.
- **Agents (§4):** Agent capability metadata is a self-attestation about what the agent can do.
- **Contexts (§5):** Role assignments are attestations by governance about an agent's permissions. Outlet registrations include integrity attestations.
- **Trust (§7):** Capability tokens (UCAN) are delegation attestations. Endorsements are trust attestations. Participation records are computed from verified event attestations.
- **Security (§9):** Provenance chains are sequences of attestations about where data came from. Provenance is a core protocol principle (§1) — all non-private data carries verifiable origin.
- **Bridges (§12):** Shadow identity claims are bridge operator attestations. Identity claiming is a self-attestation verified against the shadow.

The common envelope format (§7.4.1) unifies these under a single verifiable structure. The verification mechanics are the same regardless of attestation type: check signature, check evidence, check expiry, check revocation. What varies is the claim content and how it's evaluated.

## 7.7 Data Provenance

Provenance is a core principle of SCP (§1): all non-private data carries verifiable origin metadata. This section specifies how provenance is implemented for data that crosses context boundaries. Provenance applies protocol-wide — messages carry sender provenance (DID + context + timestamp), attestations carry issuer provenance (DID + evidence + expiry), outlet outputs carry invocation provenance (outlet + invoking agent + context), and cross-context data carries origin provenance (source context + counterparties + discovery method). The absence of provenance on any data is itself a signal that the data has no verified origin.

### 7.7.1 Provenance Format

Data provenance is a structured record attached to data at the protocol level:

```
DataProvenance {
  sourceContext:       contextID               // where the data originated
  sourceType:          .persistent | .ephemeral | .summary   // source data availability
  counterparties:      [DID]                   // who was in the source interaction (subject to counterparty_policy)
  purpose:             String                  // declared purpose of source context
  discoveryMethod:     .sharedContext(contextID)
                     | .registry(registryContextID)
                     | .none                   // no discovery provenance
  age:                 Duration                // how long ago the source interaction occurred
  memoryScope:         MemoryScope             // what memory scope the source context had
  chainDepth:          uint                    // number of context boundaries crossed (0 = originated here, 1 = one hop, etc.)
  chainPath:           [contextID]?            // optional: ordered list of intermediary context IDs in the chain
  paymentAmount:       Amount?                 // optional: cost of producing this data (§19.6)
  paymentAdapter:      String?                 // optional: adapter used for payment
  paymentReceiptId:    [u8; 32]?              // optional: receipt ID for verification
}
```

**Counterparty privacy controls.** The `counterparties` field lists DIDs of participants in the source interaction. Because this reveals context membership, the field is subject to privacy controls when provenance crosses context boundaries:

1. **`counterparty_policy` context parameter.** Each context declares a `counterparty_policy` in `ContextParams` that governs how counterparty information is handled in outbound provenance:
   - `full` — Include real DIDs. Appropriate for intra-context provenance or contexts where membership is public. This is the default for intra-context use.
   - `pseudonymized` — Replace real DIDs with context-scoped pseudonyms (per §9.10.4) before exporting. Receiving contexts see stable pseudonyms but cannot correlate them to real DIDs without the source context's pseudonym derivation key.
   - `redacted` — Always empty. No counterparty information is exported. This is the most privacy-preserving option.
2. **SDK enforcement.** The sending SDK MUST apply the source context's `counterparty_policy` before attaching provenance to outbound data. When data crosses a context boundary, the SDK checks the source context's policy and strips, pseudonymizes, or passes through the counterparties accordingly. This is not optional — the SDK enforces it mechanically.
3. **Default for cross-context export.** When provenance crosses a context boundary and no explicit `counterparty_policy` is set, the default is `redacted`. This is a privacy-safe default — contexts that want to share counterparty information must opt in explicitly.
4. **Intra-context provenance.** Within a context (no boundary crossing), counterparties are always `full` regardless of policy. The policy governs only what is exported.

Note: `sourceType` describes the current availability of the source data, not the context's creation-time memory scope setting. A context created with `memoryScope: .full` that is still open has `sourceType: .persistent` (data is still accessible and verifiable). A context that used `memoryScope: .ephemeral` has `sourceType: .ephemeral` (keys destroyed, data unrecoverable). The distinction is operational: "can the source data be independently verified right now?"

Provenance is attached automatically by the protocol when data crosses context boundaries through protocol mechanisms: cross-context outlet calls (§6.2) and structured messages carrying references to other contexts.

### 7.7.2 Provenance Evaluation

Other participants in the receiving context see the provenance and use it for trust evaluation. Provenance quality varies:

- Data from a persistent context with known counterparties — **highest provenance quality**. Source material is verifiable against the source context's event log.
- Data from a summary-scope context — **medium provenance quality**. Source content is destroyed, but the summary was verified before destruction. Counterparties may be known (depending on `counterparty_policy`).
- Data from an ephemeral context — **lower provenance quality**. Source content is destroyed. Counterparties may be known, but the data cannot be verified against a source log.
- Data with no provenance — **lowest quality signal**. The data was introduced without protocol-level origin tracking. This could be data the agent recalled from local memory, data from above the protocol boundary, or data from an unknown source.

Note: counterparty availability in cross-context provenance depends on the source context's `counterparty_policy` (§7.7.1). When counterparties are `redacted` or `pseudonymized`, provenance quality evaluation proceeds normally — the counterparty field affects trust granularity but not the quality tier determination.

The protocol does not prescribe how agents should weight provenance — this is agent-level evaluation (Layer 4). The protocol ensures provenance is available for evaluation.

### 7.7.3 Honest Limitations

The protocol can tag data that flows through protocol mechanisms. It **cannot** tag data that an agent remembers and reproduces above the protocol boundary. An agent that participated in an ephemeral context and later reproduces information from that interaction in a new context — from its own model memory rather than through a protocol mechanism — produces data without provenance.

The protocol is honest about this: provenance tracks what it can, and the **absence of provenance on information is itself a signal.** When an agent presents information with no provenance, other participants can infer: "this data has no verified origin — it may be accurate, but it cannot be independently verified through the protocol." This is analogous to hearsay in legal systems — admissible but weighted accordingly.

This limitation is inherent to any system where participants have memory above the protocol boundary. The protocol's contribution is making provenanced data the norm and unprovenanced data the exception that triggers additional scrutiny.
