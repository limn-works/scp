# 6. Cross-Context Communication

## 6.1 Agent Isolation

Agents cannot cross contexts at the protocol level. This is absolute. An agent in Context A cannot send a message to Context B, read Context B's state, or interact with Context B's tools or members. From the protocol's perspective, the agent in A and the agent in B (even if operated by the same human) are entirely separate instances.

Information may cross context boundaries through two protocol-level mechanisms:

1. **Cross-context outlet interfaces (§6.2)** — asymmetric, structured, request/response. One context queries another's outlet. Governed by both contexts per call.
2. **Multi-parent child contexts (§5.13)** — symmetric, full context. A shared space governed by multiple parent contexts. Members from different parents interact as peers.

Both mechanisms require explicit consent from all involved contexts. Neither allows agents to directly access another context's state. The first is for service-style interactions; the second is for collaborative ones.

## 6.2 Context-to-Context Outlet Interfaces

### 6.2.0 Outlet Interface Transport

Cross-context outlet calls require a physical transport mechanism to bridge the boundary between two isolated contexts. Two protocol-level mechanisms provide this:

1. **Shared-member bridging (primary).** When a human participates in both contexts, their SDK bridges outlet requests and responses locally. The human's agent in Context A makes an outlet call targeting Context B; the SDK routes the request through the human's membership in Context B, executes the call under Context B's governance, and returns the response to Context A. No relay-level cross-context routing is needed — the bridge operates entirely within the human's local SDK. Both contexts' governance is enforced: Context A's outbound policy and Context B's inbound policy are validated before the call proceeds. The human's SDK is the transport, and both event logs record the interaction with full provenance.

2. **Multi-parent child contexts (fallback).** For cases without a shared member, a child context with parents from both the source and target contexts can serve as a bridge (§5.13). The child context inherits capability ceilings from both parents (intersection). Members from both parent contexts who join the child context can mediate outlet calls within the child's governed space. This is heavier than shared-member bridging but covers the case where no single human has membership in both contexts.

These two mechanisms cover all cross-context outlet call scenarios. Direct agent-to-agent communication is not needed — outlet interfaces with stateful sessions (§6.2.1) provide the same functional coverage (negotiation, coordination, multi-step workflows) with stronger security guarantees: every interaction is context-governed, schema-declared, rate-limited, and auditable. The context governs the outlet call, not the agent.

Contexts can expose outlet endpoints to other contexts. **The context governs the outlet call, not the agent.** An agent in Context A does not directly contact Context B — the agent requests from Context A, Context A's governance decides whether to permit the outbound call, and Context B's governance decides whether to permit the inbound call and how to respond. Both contexts mediate. The agent never directly touches the other context.

This is the mechanism for all structured inter-agent interaction across context boundaries. Both contexts' governance models, capability ceilings, and role permissions gate every interaction.

Properties:

- Both contexts opt in explicitly (bidirectional consent at the context level, not the agent level — see §6.2.0.1 for the consent protocol).
- Data flows through defined function signatures, not through agent memory or discretion.
- Auditable: every call through an interface is logged in both contexts' event logs with full provenance (§7.7).
- Outlet interfaces carry provenance: data received through an interface carries its origin context, invoking agent, timestamp, and chain depth (§7.7.1).
- Rate-limited: both contexts can enforce rate limits on interface calls (see §6.2.0.2 for defaults).
- **Chain depth limit.** Cross-context outlet calls carry a `chain_depth` counter, incremented on each hop. An outlet call at maximum depth cannot trigger further cross-context outlet calls. Context-configurable via `ContextParams::max_chain_depth` (default: 8, range [1, 255]). There is no protocol hard maximum — chain depth is a context concern, and provenance quality naturally degrades with depth. This bounds amplification and makes transitive provenance degradation mechanically enforced (§9.2.1, §24.4, ADR-043).
- **Schema constraints.** Outlet schemas must satisfy a structural specificity floor at registration time — no unbounded string-only interfaces, minimum two distinct fields in input or output. This prevents degenerate broad-schema outlets that function as arbitrary message channels (§9.2.1).
- **Outlet-level costs.** Individual outlets may declare per-invocation costs in their registration metadata (§5.4). These are additive with context-level costs and carry their own payee DID. Cross-context outlet calls inherit the target outlet's cost structure. See §19.3 for economic policy and §19.2.2 for the payment integration sequence.

#### 6.2.0.1 Bidirectional Consent Protocol

Outlet interface creation requires explicit consent from both the exposing context and the consuming context. The consent protocol:

1. **Interface proposal.** An admin in Context A proposes exposing an outlet to Context B via a governance action:
   ```
   ProposeOutletInterface {
     outlet_id:      OutletId,     // Outlet to expose
     target_context: ContextId,    // Context B
     outbound_policy: OutboundPolicy,
     max_calls_per_minute: u32,    // Rate limit for this interface
   }
   ```
   This proposal follows Context A's governance model (§5.9).

2. **Outbound policy validation.** Context A validates that `outlet:interface` is in its ceiling (§5.3) and the proposer holds the `outlet:interface` capability.

3. **Interface offer.** On governance approval, Context A publishes an `InterfaceOffer` to its event log:
   ```
   InterfaceOffer {
     offer_id:       [u8; 32],     // domain-separated, length-prefixed hash — see below
     source_context: ContextId,    // Context A
     target_context: ContextId,    // Context B
     outlet_schema:  OutletRegistration, // Full outlet schema (§5.4.1)
     outbound_policy: OutboundPolicy,
     expires_at:     u64,          // Offer expires if not accepted within 7 days
   }
   ```

   **`offer_id` construction.** `offer_id` is a SHA-256 over a domain-separated, length-prefixed preimage so that field splits cannot produce collisions (matching §5.4.1 and §9.5.1):

   ```
   offer_id = SHA-256(
     "SCP-OUTLET-OFFER-ID-V1:"
     || len_be32(context_a_id) || context_a_id     // UTF-8 bytes
     || len_be32(outlet_id)    || outlet_id        // UTF-8 bytes
     || len_be32(context_b_id) || context_b_id     // UTF-8 bytes
     || timestamp_be                                // 8 bytes, big-endian u64
   )
   ```

   The `SCP-OUTLET-OFFER-ID-V1:` separator is registered in §9.18.2.

4. **Acceptance.** A shared member carries the offer to Context B (shared-member bridging). Context B's governance decides whether to accept:
   ```
   AcceptOutletInterface {
     offer_id:       [u8; 32],
     inbound_policy: InboundPolicy,
   }
   ```
   This follows Context B's governance model. Acceptance creates an `InterfaceEstablished` event in both event logs. The `InterfaceEstablished` event records:

   - `epoch_a` — Context A's MLS epoch counter at accept time (u64). Persisted for audit.
   - `epoch_b` — Context B's MLS epoch counter at accept time (u64). Persisted for audit.
   - `ikm_a: [u8; 32]` — the exporter-derived IKM that Context A produced at accept time (computed as shown below), persisted verbatim in the event metadata.
   - `ikm_b: [u8; 32]` — the exporter-derived IKM that Context B produced at accept time, persisted verbatim in the event metadata.
   - `ikm_a_sig: Ed25519Signature` — Context A's current admin's signature over `ikm_a` (preimage below), attesting that `ikm_a` was genuinely exported from Context A's MLS layer and not chosen adversarially.
   - `ikm_b_sig: Ed25519Signature` — Context B's current admin's signature over `ikm_b`, symmetric to `ikm_a_sig`.

   The committed `(ikm_a, ikm_b)` pair pins the `hop_salt` derivation at accept time, so historic verifiability does not depend on retaining the underlying MLS epoch exporter keys. Verifiers rederive `hop_salt` deterministically from the committed IKMs at any later time using the HKDF step below. The MLS epoch keys MAY be rotated, destroyed, or forward-secrecy-ratcheted after acceptance without invalidating past `source_chain` pseudonym verification.

   **Committed-IKM signing (Byzantine-admin mitigation).** A Byzantine admin who controls MLS exporter output (e.g., by running a hostile MLS implementation) could publish a low-entropy or attacker-chosen `ikm_a` value — shifting the `hop_salt` onto an entropy distribution the attacker can pre-image. To close this, each side's admin signs its own IKM at accept time. The preimage is deliberately short and fixed-width:

   ```
   ikm_a_sig_preimage = SHA-256(
     "SCP-OUTLET-IKM-COMMITMENT-V1:"
     || len_be32(context_a_id) || context_a_id
     || len_be32(context_b_id) || context_b_id
     || epoch_a_be                            // 8 bytes BE u64
     || ikm_a                                  // 32 bytes
   )

   ikm_a_sig = Ed25519_sign(admin_a_active_key, ikm_a_sig_preimage)
   ```

   — and symmetrically for `ikm_b_sig` (Context B's admin signs `(context_a_id, context_b_id, epoch_b, ikm_b)` under its `#active` key). The `SCP-OUTLET-IKM-COMMITMENT-V1:` domain separator is registered in §9.18.2. The `#active` key is the human-accountable signing key per §3 — agent `#agent` keys MUST NOT sign IKM commitments, matching the metadata-signing discipline in §5.7.2.

   Verifier rule: an `InterfaceEstablished` event whose `ikm_a_sig` does not verify under Context A's admin `#active` key (resolved at `epoch_a` against the context's role registry), OR whose `ikm_b_sig` does not verify under Context B's admin `#active` key (resolved at `epoch_b`), is rejected at event-log append time with `OutletErrorClass::Authorization` slug `authorization.ikm-signature-invalid` (code `SCP-TOOL-6110`). A failed signature rejects the interface establishment entirely; the event does NOT land in either event log. This ensures the published IKMs are cryptographically attributable to the signing admin — a malicious admin who later denies publishing a low-entropy IKM is disproved by the signature. Signing the context-id pair and the epoch binds each signature to this specific interface and this specific acceptance epoch, so an `ikm_a` value cannot be extracted from one interface and re-signed into another.

   **Admin-removal salt rotation.** When an admin is removed from either context (via governance `RemoveMember`-with-admin-role or equivalent), every interface that context holds MUST trigger a forced `hop_salt` re-derivation. The removed admin retains their prior knowledge of the committed `(ikm_a, ikm_b)` and could therefore compute `HMAC(hop_salt, raw_context_id)` for any context id they know — continuing to reverse pseudonyms for hops they no longer have a right to observe. To close this, on any admin removal, the governance engine emits an `InterfaceSaltRotated` event to every active interface the context holds. The event structure is:

   ```
   InterfaceSaltRotated {
     interface_id: [u8; 32],       // the prior InterfaceEstablished's offer_id
     new_ikm_local:    [u8; 32],    // fresh exporter output at current epoch, labeled per §6.2.0.1
     new_ikm_local_sig: Ed25519Signature, // remaining admin's signature over the new IKM
     epoch_local:      u64,         // local context's current MLS epoch
   }
   ```

   The peer context receives the `InterfaceSaltRotated` event via shared-member bridging and emits its own `InterfaceSaltRotated` (with its own fresh IKM, signed by its own admin) in response. Once both sides have published rotated IKMs, both contexts re-derive `hop_salt` using the HKDF step below over the NEW `(ikm_a, ikm_b)` pair. The removed admin's knowledge of the prior `hop_salt` becomes useless — any `context_id` they compute `HMAC(old_hop_salt, ...)` for does not match the new wire pseudonyms. Until both sides have rotated, the interface operates under the prior `hop_salt` (a best-effort window — typically one epoch); rotated IKMs take effect at the next `OutletError` envelope emitted by either side.

   The removed admin's DID is recorded in the `InterfaceSaltRotated` event's audit metadata as `trigger_removal_did`. This makes the rotation trail verifiable against the governance event that caused it. The rotation is unconditional — governance cannot suppress it, and admins cannot opt out.

   **`hop_salt` derivation and lifecycle.** The `hop_salt: [u8; 32]` is used to pseudonymize `source_chain.context_id` entries for observers who are not members of each hop (§5.4.4). At accept time, each side computes its peer-labeled MLS exporter IKM and commits it into the `InterfaceEstablished` event. Thereafter, `hop_salt` is derived deterministically from the committed `(ikm_a, ikm_b)` — **not** from the live MLS exporter, so it does not degrade with MLS epoch ratcheting and does not require either context to retain obsolete MLS epoch secrets. Revocation of the interface rotates the salt on re-establishment (a fresh pair of IKMs is committed to the new `InterfaceEstablished` event).

   ```
   // Step 1 — accept-time IKM derivation (run once, by each side, at AcceptOutletInterface).
   // Each context uses its PEER's context_id as the MLS exporter label suffix — this
   // ensures that ikm derived from Context A's exporter for the A↔B interface cannot
   // be reused to pseudonymize any A↔C interface (different label → different key).
   canonical_peer_id_a = context_b_id   // Context A uses Context B's id as suffix
   canonical_peer_id_b = context_a_id   // Context B uses Context A's id as suffix

   ikm_a = MLS_EXPORTER(
     "scp-context-hop-salt-v1:" || canonical_peer_id_a,
     b"",
     32,
   )  // exporter on Context A's accept-time epoch, labeled with Context B's id.
      // Persisted in the InterfaceEstablished event metadata.
   ikm_b = MLS_EXPORTER(
     "scp-context-hop-salt-v1:" || canonical_peer_id_b,
     b"",
     32,
   )  // exporter on Context B's accept-time epoch, labeled with Context A's id.
      // Persisted in the InterfaceEstablished event metadata.

   // Step 2 — hop_salt derivation (run on demand from committed IKMs).
   // Canonical concatenation: lexicographically smaller context_id first, so both sides agree.
   ordered = if context_a_id < context_b_id { (ikm_a, ikm_b) } else { (ikm_b, ikm_a) }

   hop_salt = HKDF-SHA-256(
     salt = b"",
     ikm  = ordered.0 || ordered.1,
     info = "SCP-CONTEXT-HOP-SALT-V1:" || canonical_context_pair(a_id, b_id),
     L    = 32,
   )

   // canonical_context_pair sorts the two context_ids lexicographically, emits them as
   //   len_be32(min_id) || min_id || len_be32(max_id) || max_id
   ```

   **Why the label suffix is required (cross-interface reuse closure).** Without the peer-context suffix on the exporter label, both `ikm_a` for the A↔B interface and `ikm_a'` for an independent A↔C interface would be derived from the same MLS exporter key material (Context A's `"scp-context-hop-salt-v1"` export at the current epoch). Any party who established an interface with Context A and learned `ikm_a` would then be able to derive the `hop_salt` for every other interface Context A had with any other context — breaking the per-pair isolation the pseudonymization relies on. Including the peer's `context_id` in the MLS exporter label makes each per-pair IKM derive from a unique export key (each context produces a distinct exporter key per peer), so knowledge of `ikm_a` for one interface does not compromise pseudonymization for any other.

   **Symmetry.** Context A and Context B use reciprocal labels — A's label is suffixed with B's id, B's label is suffixed with A's id. Because `hop_salt` HKDF-combines `ikm_a || ikm_b` after lexicographic ordering, and both sides agree on the ordering (ascending `context_id`), both sides compute byte-identical salts. The canonical-ordering step is what makes the construction symmetric despite the asymmetric label suffixes.

   **Historic verifiability.** The IKMs are committed verbatim in the `InterfaceEstablished` event metadata at accept time, so any `source_chain` entry emitted during this interface's lifetime is verifiable at any later time by re-running Step 2 against the recorded `(ikm_a, ikm_b)` pair. The MLS layer in SCP does not expose per-epoch-recoverable exporter ratcheting, so the committed-IKM approach is what makes historic verification mechanical; the alternative — retain MLS epoch secrets indefinitely to re-run Step 1 — would conflict with forward secrecy.

   **Trade-off disclosure.** The committed IKMs are 32-byte pseudo-random values that enter the public event log alongside the epoch counters. This leaks a per-interface, per-accept-time exporter value into the log. The pseudonymization threat model was never to hide `hop_salt` from members of either context (both contexts already derive `hop_salt` locally); it is to prevent non-members from correlating context IDs across hops. Publishing IKMs does NOT degrade that property, because the HMAC of `raw_context_id` under `hop_salt` is still a one-way map for non-members who have neither IKM-keyed knowledge nor membership in either context. Members of BOTH contexts could already reverse the pseudonym for their own interface; the publication changes nothing for them. The publication does NOT extend membership-level pseudonym-reversal to non-members because the HMAC inputs (raw `context_id` values) are still unknown to non-members. Net effect: the security property is unchanged relative to the derive-on-demand construction; the availability property (historic audit after MLS epoch rotation) is strictly improved.

   The `SCP-CONTEXT-HOP-SALT-V1:` prefix (used both in the MLS exporter label family and in the HKDF info string) is registered in §9.18.2. Each context's interface-state entry retains the accept-time `(epoch_a, epoch_b, ikm_a, ikm_b)` and the peer's `context_id`.

5. **Teardown.** Either context can revoke the interface at any time via governance action `RevokeOutletInterface { interface_id }`. Revocation is unilateral — no consent from the other side is needed. An `InterfaceRevoked` event is recorded in the revoking context's event log.

**Interface-spam deterrent (quadratic cost, cluster-aware).** Interface establishment is an economic action with an anonymity-set interaction: every additional active A↔X interface that Context A holds narrows the anonymity set under which `hop_salt` pseudonyms from A appear. To deter interface-spam as an anonymity-set-reduction attack, the cost a context pays to establish its `n`-th active interface scales **quadratically** in the count of active prior interfaces within a cluster-detection window.

**Rolling window + cluster detection.** Context A maintains a 24-hour rolling interface-establishment log per peer-cluster. When Context A proposes `AcceptOutletInterface` against a candidate peer B, the governance engine computes the cluster-match count `k` by examining every prior `InterfaceEstablished` or `AcceptOutletInterface` event in the rolling window and incrementing `k` by one whenever ANY of these three predicates holds between the prior peer `P_i` and the candidate peer `B`:

1. **Context-id match.** `P_i.context_id == B.context_id`. Direct re-negotiation with the same peer context.
2. **Creator-DID match.** `P_i.creator_did == B.creator_did`, where `creator_did` is the DID captured at each peer context's creation event (the first admin who created the context per §5.4 context lifecycle). This catches the "rotate admin to spin up 100 disjoint contexts" evasion: the creator DID is fixed at context creation and cannot be rotated out.
3. **Admin-set intersection.** `P_i.admin_set ∩ B.admin_set ≠ ∅`, comparing the admin role holders of each peer context at interface-acceptance time. This catches the "new DID creates a context and invites the same admin cluster" evasion: shared admin DIDs across the ostensibly-independent peer contexts reveal the cluster.

If ANY of the three predicates holds, the prior interface contributes to `k`. The cost to establish the new A↔B interface is:

```
interface_cost = max(base_cost, interface_base_cost_minimum) × (k + 1)²
```

where `base_cost` is set by context economic policy (§19.3) and bounded below by the `ContextParams::interface_base_cost_minimum` (registered in §9.18.B, default: smallest non-zero economic unit in the context's currency — preventing `base_cost = 0` from defeating the quadratic escalator). The quadratic escalation makes repeated interface establishment with the same peer cluster economically irrational at low counts (k=1 → 4× base; k=4 → 25× base; k=9 → 100× base), which is sufficient to prevent the attack surface without penalizing legitimate bilateral renegotiation.

Cluster-match data (each peer's `context_id`, `creator_did`, and `admin_set` at interface-acceptance time) is captured into the `InterfaceEstablished` event metadata at accept-time. The governance engine reads these directly from its own event log to evaluate predicates 1-3 — no external lookup is required, and the cluster calculation is therefore deterministic and replayable.

This rule is additive to the standard `OutletErrorClass::Economic::InsufficientFunds` path — a context without sufficient funds for the quadratic fee fails interface establishment at governance approval time, not at hop time. The specific rejection uses code `SCP-TOOL-6150` (Economic) slug `protocol.interface-spam-cost` when the fee exceeds the proposer's balance. The cluster-aware calculation closes the "rotate creator_did AND rotate admin_set" evasion only for attackers who also invest a fresh admin DID per context (BH5-M3 residual-risk: an attacker willing to burn N distinct admin DIDs plus N distinct creator DIDs bypasses the cluster detection; the economic floor of `interface_base_cost_minimum × 1²` per interface is the lower bound and must be set at a level where N fresh DIDs is itself economically irrational).

**Outbound and inbound policies:**

```
OutboundPolicy {
  allowed_callers:      Vec<DID>,   // DIDs in Context A authorized to use this interface.
                                    // Empty = any member with outlet:interface capability.
  max_calls_per_minute: u32,        // Rate limit from Context A's perspective.
  max_payload_bytes:    u32,        // Maximum request payload size. Default: 65536 (64 KiB).
  require_provenance:   bool,       // Whether responses must carry provenance. Default: true.
}

InboundPolicy {
  allowed_source_roles: Vec<String>, // Roles in Context A whose members can call. Empty = any.
  max_calls_per_minute: u32,        // Rate limit from Context B's perspective.
  max_response_bytes:   u32,        // Maximum response payload size. Default: 65536 (64 KiB).
  require_spending_ucan: bool,      // Whether callers must present spending UCANs. Default: false.
}
```

Outbound policy is set by Context A (the exposing context). Inbound policy is set by Context B (the consuming context). Both policies are enforced — a call must satisfy BOTH to proceed. The effective rate limit is `min(outbound.max_calls_per_minute, inbound.max_calls_per_minute)`.

#### 6.2.0.2 Outlet Interface Rate Limit Defaults

Rate limits for cross-context outlet interfaces use a sliding window counter with the following defaults:

| Parameter | Default | Configurable range |
|-----------|---------|-------------------|
| Per-interface calls/minute | 60 | 1 - 6000 |
| Per-caller calls/minute | 10 | 1 - 1000 |
| Burst allowance | 5 (calls above limit within 1 second) | 0 - 50 |
| Window duration | 60 seconds (sliding) | 10 - 3600 seconds |

**Enforcement semantics.** When a rate limit is exceeded, the call is rejected with error code `OUTLET_INTERFACE_RATE_LIMITED` (code 4030). The response includes a `Retry-After` header indicating seconds until the next call will be accepted. Calls are NOT queued — rate-limited calls fail immediately. The caller's SDK MAY retry after the indicated delay.

**Per-caller vs. per-interface limits.** Both limits are enforced independently. A single caller is limited to 10 calls/minute by default; all callers combined are limited to 60 calls/minute per interface. This prevents a single caller from monopolizing an interface.

**Classification-aware rate tiers (§5.4.2).** Defaults differ for Query and Action outlets. Query outlets: per-interface 600 calls/min, per-caller 100 calls/min — an order of magnitude higher, reflecting the idempotent read-only contract. Action outlets: per-interface 60 calls/min, per-caller 10 calls/min (the original defaults). Both tiers are independently configurable within the range shown in the table.

#### 6.2.0.3 Chain Amplification Rule

Cross-context outlet calls inherit an **`origin_kind`** (an `OutletKind` per §5.4.2) from the outermost caller. At each cross-context hop, the runtime enforces:

- **Query → Query: permitted.** A Query invocation may transitively invoke Query outlets in downstream contexts.
- **Query → Action: forbidden.** A Query invocation MUST NOT trigger any Action invocation, directly or transitively. The runtime rejects the amplification attempt at the cross-context consent gate (§6.2.0.1) with `OutletErrorClass::Authorization::AmplificationViolation`.
- **Action → Query: permitted.** An Action invocation may transitively invoke Query outlets.
- **Action → Action: permitted.** An Action invocation may transitively invoke Action outlets, subject to chain depth.

The rule closes the "free read laundered into paid write" class of attacks: Query is the cacheable, cost-capped tier, and allowing a Query to cascade into an Action would let an adversary exercise Action semantics under Query rate limits and economics.

**`origin_kind` is bound to the UCAN delegation chain, not to runtime state.** The outermost caller sets `origin_kind` equal to the stem it exercises — `Query` when it exercises `outlet_query:*`, `Action` when it exercises `outlet_call:*`. The stem lives inside a signed UCAN delegation, so the outermost `origin_kind` is not a claim any participant makes at runtime; it is a property of the token. Every cross-context hop propagates `origin_kind` inside the delegated UCAN's `nb` field as the dedicated `origin_kind` slot of `InvocationCaveats` (§7.3.8). Because `origin_kind` is a field of the signed `InvocationCaveats`, it is covered by each hop's delegation signature.

The caveats-layer `narrow()` rule (§7.3.8) enforces equality between child and parent `origin_kind` at every delegation step:

```
child.nb.InvocationCaveats.origin_kind  ==  parent.nb.InvocationCaveats.origin_kind
```

— that is, `origin_kind` is preserved across every delegation step; a child delegation MUST NOT reset, widen, or narrow it. An `origin_kind` mismatch between a child and its parent is an attenuation violation at Step 7b of the UCAN validation pipeline (§7.2.1) and returns `OutletErrorClass::Authorization::AttenuationViolation`. This makes the "origin_kind is signed" claim operationally true: the equality check runs on the `narrow()` verifier, which is the single chokepoint where the signed child-parent relationship is validated.

Because `origin_kind` is covered by each hop's UCAN signature, the hop target cannot be tricked into treating a `Query`-originated call as `Action`-originated by a forged claim at the transport layer — forging `origin_kind` would require forging the signed delegation.

The amplification check `origin_kind != Query || hop_kind == Query` MUST be evaluated at the hop target (inside the acceptance path, after UCAN validation and before the outlet is dispatched), not only at the hop source. A malicious source that skipped the check client-side is caught at the target.

#### 6.2.0.4 Chain Depth Split

The context-level `max_chain_depth` parameter (default 8) is partitioned by kind:

- **Query chain budget:** `max_chain_depth` (full budget).
- **Action chain budget:** `max(1, max_chain_depth / 2)` (default 4).

On each cross-context hop, the runtime decrements the kind-appropriate counter. A Query → Query → Action chain at budget `(8, 4)` decrements Query on hops 1 and 2 and then, because Query → Action is forbidden under §6.2.0.3, is rejected before the Action hop consumes budget. The split ensures Action invocations have stricter amplification bounds than Query invocations without requiring two unrelated parameters.

### 6.2.0.5 Cross-Context Streaming

Outlet streams (§5.4.5) cross context boundaries under the same §6.2 tool-interface model. A shared-member bridge transports chunks from the target context to the source context, re-encrypting each chunk per-recipient as it crosses (source-context encryption on the outbound leg; target-context decryption on the inbound leg). The bridge does NOT buffer the full stream — chunks flow through as they arrive, subject to the credit window.

- **`chain_depth` is set at open.** Every chunk inherits the chain depth recorded at the opening cross-context hop. Chunks do not recompute depth. Opening is subject to §6.2.0.3 and §6.2.0.4; chunks after open are not re-checked.
- **Credit is end-to-end.** Credit grants from the invoker propagate across the bridge to the executor without re-accounting at the bridge.
- **UCAN check locus.** UCAN is validated ONCE at stream open (§5.4.5). Mid-stream revocation terminates at the next `stream_ucan_recheck_secs` cadence tick, receiver-side (§5.4.5 revocation re-check cadence); already-emitted chunks remain authorized.
- **Concurrent-stream caps apply at both ends of the bridge.** Per §5.4.5 the hop target enforces `max_concurrent_inbound_streams_per_origin_invoker` against the outermost caller DID in the UCAN delegation chain, not the immediate-previous hop. Cross-context delegation-chain rewriting does not reset this ceiling — a caller who narrows through intermediate agents still counts against the single origin-invoker slot at the terminal operator.
- **Event log recording.** Each of the two contexts records exactly one `OutletInvokedEvent` for the stream, with the same `stream_manifest_hash` (§5.4.5). Cross-context provenance (§7.7) chains the two events via the `source_chain` field on the error envelope (when the stream fails) or on the final `End.provenance` (when it succeeds).

### 6.2.1 Stateful Outlet Sessions

Outlet interfaces support optional session-based multi-turn interaction. An outlet can accept a session identifier and maintain state across sequential invocations. This enables multi-step workflows (negotiation, coordination, iterative refinement) within the governed outlet call framework.

```
// First call: initiate a scheduling session
Context A → Context B outlet "schedule_meeting":
  input:  { action: "propose", times: ["Tue 3pm", "Thu 2pm"] }
  output: { session_id: "sched:abc123", status: "pending", counter: ["Tue 4pm"] }

// Second call: continue the session
Context A → Context B outlet "schedule_meeting":
  input:  { session_id: "sched:abc123", action: "accept", time: "Tue 4pm" }
  output: { session_id: "sched:abc123", status: "confirmed", time: "Tue 4pm" }
```

Session state is maintained by the outlet's context (Context B), not by the calling agent. Each call in the session is individually governed — Context A's governance permits each outbound call, Context B's governance permits each inbound call. The session does not create a persistent channel; it is a sequence of governed outlet calls that share state via an opaque session identifier.

Sessions have an optional TTL set by the outlet's context. When set, expired sessions are garbage-collected automatically. Sessions without a TTL persist for the lifetime of the context — appropriate for app-hosted sessions (games, workspaces, collaborative tools) where the context itself is the session's lifecycle boundary. Contexts enforce a per-caller session cap, context-configurable via `ContextParams::session_cap` (default: 1000 concurrent sessions per calling context), to prevent session exhaustion attacks regardless of TTL (§9.2.1, ADR-043). Session state is internal to the outlet's context and not visible to the calling context beyond the outlet's defined output schema.

**Session chain-amplification binding.** A session inherits the `origin_kind` (§6.2.0.3) of the first call that created it. Every subsequent call routed through the session (identified by `session_id` in the input) is treated by the runtime as carrying the session's recorded `origin_kind`, regardless of any new UCAN presented by the caller or any `origin_kind` claim in a later delegation. Concretely: if a session was opened by a `Query`-originated call, every call through that session is treated as `origin_kind = Query` for amplification-rule purposes, and any attempt to call an Action outlet through the session is rejected with `AmplificationViolation`. This prevents async self-triggered amplification — a `Query`-originated session cannot "mature" into an Action session by the caller later presenting an Action-rooted UCAN.

Sessions store their recorded `origin_kind` alongside the session state. A session opened with `origin_kind = Action` retains Action semantics for its lifetime; a session opened with `origin_kind = Query` retains Query semantics for its lifetime. There is no session upgrade path — re-opening as Action requires a new session with a fresh `session_id`.

#### 6.2.1.1 Stateful Outlet Sessions × Streaming

When a streaming outlet (§5.4.5) participates in a session, the session and stream lifecycles interact through five invariants. The session owns the long-lived authorization state; each stream owns its per-invocation chunk flow.

(a) **`session_id` carried on open.** `OutletStreamOpen` carries an optional `session_id: Option<String>` field. When present, the open MUST reference an existing, non-expired session whose `session_id` matches, whose TTL has not elapsed, and whose recorded `origin_kind` is compatible with the outlet's kind per §6.2.0.3. An `OutletStreamOpen` referencing an unknown, expired, or amplification-incompatible session is rejected at open with `OutletErrorClass::Protocol::UnknownSession` or `OutletErrorClass::Authorization::AmplificationViolation` respectively.

**`session_id` format and uniqueness.** `session_id` is a **UUIDv7** encoded per RFC 9562 §5.7 — a 128-bit identifier whose first 48 bits encode a Unix-millisecond timestamp and whose remaining 80 bits are CSPRNG-sampled per caller. The canonical string form is the 36-character `8-4-4-4-12` hex representation with lowercase hex. Callers generate `session_id` by concatenating (a) the current `unix_ms` time as the 48-bit timestamp prefix, (b) their DID's canonical 80-bit fingerprint (first 10 bytes of `SHA-256(did_string)` XORed with a process-local monotonic 80-bit counter), to produce a `(did, process_time)`-unique identifier that is time-sortable and collision-resistant. SDKs MUST validate the UUIDv7 format on both construction (in the caller's SDK) and acceptance (in the hosting context); a malformed `session_id` is rejected with `OutletErrorClass::Protocol::MalformedSessionId` (code `SCP-TOOL-6101`, slug `protocol.malformed-session-id`).

**Collision handling.** Two concurrent callers selecting the same `session_id` (possible in adversarial scenarios or under extreme process-counter collisions) is detected at session-creation time: the hosting context's session store uses `session_id` as the primary key, and a second caller opening a session with the same id is rejected with `OutletErrorClass::Protocol::SessionIdConflict` (code `SCP-TOOL-6101`, slug `protocol.session-id-conflict`). The first caller's session wins; the second caller MUST re-sample a fresh `session_id` and retry. Because UUIDv7's collision probability is ~2⁻⁴⁰ per millisecond per caller, collision-reject is an edge case, but specifying the reject rule closes the "duplicate-session-id silent takeover" surface.

(b) **One concurrent stream per session.** A session supports AT MOST one concurrent stream. A second `OutletStreamOpen` referencing a `session_id` that already has a live stream is rejected with `OutletErrorClass::Protocol::StreamAlreadyOpen` (class Protocol, slug `protocol.stream-already-open`). The rule closes the "parallel billing channels through one session" surface. A stream is considered live from open until the terminal chunk is written (End or Error{terminal:true}) or the stream is cancelled and the cancel-ack chunk arrives.

(c) **Session owns `origin_kind`.** The session's recorded `origin_kind` (§6.2.1 "Session chain-amplification binding") is the authoritative value for every stream opened against the session. The opening `OutletStreamOpen`'s `effective_caveats.origin_kind` MUST equal the session's recorded `origin_kind`; a mismatch is an attenuation failure (not a silent override). This means a session opened as `Query` cannot host a stream whose narrowed caveats claim `Action` — the session's `origin_kind` shields the hop target from any later attempt to re-classify.

(d) **Session owns `caveats_binding`.** The session's first stream establishes the session's pinned `caveats_binding` at session-open time (recorded from that stream's `OutletStreamOpen.caveats_binding`). Every subsequent stream opened against the same session MUST present an identical `caveats_binding`; a mismatch is rejected as `OutletErrorClass::Authorization::AttenuationViolation` under the caveats-binding-pinning invariant (§5.4.5). This extends stream-level pinning to the session lifetime — a single session cannot host multiple streams under different caveat sets, only retries of the same caveat contract.

(e) **`stream_epoch` matches session's MLS epoch at open.** Each stream records `stream_epoch` equal to the hosting context's MLS epoch counter at the moment of `OutletStreamOpen` acceptance. The session independently records the MLS epoch at which it was opened (`session_epoch`). A stream whose `stream_epoch != session_epoch` is permitted (sessions persist across epoch advances), but the re-encryption bridge on cross-context streaming (§6.2.0.5) uses `stream_epoch` for chunk-level re-encryption, not `session_epoch`. Recording the two separately means a long-lived session spanning many MLS epochs still produces a per-stream chunk manifest bound to its own epoch, so a single compromised epoch exposes chunks from only the streams opened within that epoch, not the session's entire history.

Together these invariants make sessions a legitimate long-lived authorization envelope without allowing them to be used as a channel that escapes stream-level billing, amplification, or caveats enforcement.

### 6.2.2 Protocol-Level Discovery

Discovery is built from two complementary mechanisms: DID document capabilities (direct lookup) and contexts with discovery tools (searchable registries). Together, these provide 0-setup discovery that makes SCP inherently social.

#### A. DID Document Capabilities

Every agent MAY publish structured capabilities in their DID document's `service` array. These are resolved via did:dht — always available, 0-setup, no context required. Any agent that knows a DID can resolve the document and inspect capabilities directly.

```json
{
  "id": "#scp-capabilities",
  "type": "SCPCapabilities",
  "serviceEndpoint": {
    "capabilities": [
      "scp:capability:translation/v1",
      "did:dht:abc123:capability:japanese-translation/v1"
    ],
    "version": "scp/1.0"
  }
}
```

DID document capabilities provide direct lookup for any known DID. They do not provide search or browsing — for that, contexts with discovery tools are needed.

#### B. Contexts with Discovery Tools

These are standard SCP contexts with open join policies and standardized discovery tools. Anyone can create one. No central authority, no operator dependency. They inherit all context-governed properties: tool calls are rate-limited and auditable, results carry provenance.

**Standard discovery tool schemas** — minimum interoperable interface:

```
agent_search(query) → results
  input:  { capability_uri: string?, keywords: [string]?, min_history: int? }
  output: { results: [{ did: DID, capabilities: [string], participation_summary: object }] }
  // capability_uri: structured URI per §4.4.1 (e.g., "scp:capability:translation/v1")
  // keywords: free-text search terms (not capability URIs)

agent_register(did, capabilities, metadata) → confirmation
  input:  { did: DID, capabilities: [string], metadata: { description: string?, tags: [string]? } }
  output: { registered: bool, entry_id: string }
  // capabilities: array of structured capability URIs per §4.4.1

agent_deregister(did) → removal
  input:  { did: DID }
  output: { removed: bool }
```

These are conventions, not mandates — contexts with discovery tools can add custom tools (e.g., reputation scoring, category browsing, geographic filtering) beyond the standard schema. Contexts that support human-readable addressing (§22) additionally implement `handle_register`, `handle_lookup`, `handle_deregister`, and `attestation_lookup` tools. Contexts that serve as scope registries (§22.3.5) additionally implement `scope_register`, `scope_lookup`, `scope_deregister` — independent tools with separate storage, constrained to context-only targets and dot-free scope names (ADR-043).

**Two-tier membership model.** Contexts use a two-tier architecture to support unbounded scale while maintaining MLS-based governance:

- **Writer tier (MLS members, bounded).** Writers are standard MLS group members. They can register/deregister entries, modify governance, and process registration requests. The MLS group is bounded at ~500 members to maintain practical epoch advance costs (O(N) cost per MLS Update). Writers are typically registry operators, curators, and high-volume registrants.
- **Reader tier (DID-authenticated, unbounded).** Readers query the context's tool endpoints via DID-signed requests without joining the MLS group. They can search (`agent_search`), inspect entries, and request inclusion proofs from the Merkle event log. No MLS membership required, no epoch advance cost. Reader capacity is unbounded.
- **Registration flow.** A reader (non-MLS-member) registers by sending a DID-signed registration request to the context's `agent_register` tool endpoint. A writer processes the request and records it as an MLS application message in the event log. The registrant does NOT become an MLS member — their entry is stored in the context's registry data, and they can update or deregister via subsequent DID-authenticated requests to tool endpoints, processed by writers.
- **Self-service updates.** Registered agents update their entries via DID-authenticated requests to tool endpoints. Updates are subject to ownership enforcement:
  1. **Entries are owned by their creator DID.** The DID that called `agent_register` is the entry owner, recorded at creation time.
  2. **Only the owner can update or delete their own entries.** Writers MUST verify that the DID signature on the update request matches the entry's owner DID before processing.
  3. **Context admins can update or delete any entry.** DIDs holding the `Admin` role in the context bypass ownership checks.
  4. **Signature verification.** All update and delete requests MUST carry a valid signature from the requester's Active Signing Key (`#active`) or Agent Signing Key (`#agent`). Writers verify the signature against the requester's current DID document before processing.
  5. **Rejection on mismatch.** If the requester's DID does not match the entry owner and the requester is not a context admin, the request is rejected with an `OwnershipViolation` error. The rejection is logged in the Merkle event log.
- **Consistency.** All writes are recorded in the Merkle event log. Readers can request inclusion proofs to verify their registration was recorded and to audit the registry's integrity.

**Registration request authentication.** All registration, update, and deregistration requests from non-MLS readers are authenticated via DID-signed request envelopes. The authentication protocol:

1. **Request signing.** The requester constructs a request payload containing the operation type (`register`, `update`, `deregister`), the entry data, and a freshness tuple `(timestamp, nonce)`. The payload is signed with the requester's Active Signing Key (`#active`) or Agent Signing Key (`#agent`), using the canonical hash construction (§9.5.1) with domain separator `"SCP-DISCOVERY-REQUEST-V1:"`. The signed preimage includes: `context_id || requester_did || operation_tag || entry_data_hash || nonce || timestamp`, where `entry_data_hash` is `SHA-256(serialized_entry_data)` and `nonce` is a 16-byte CSPRNG value.

2. **Signature verification.** Writers MUST resolve the requester's DID document and verify the Ed25519 signature against the `#active` or `#agent` verification method. If the DID document cannot be resolved or the signature is invalid, the request is rejected.

3. **Replay protection.** Writers MUST validate that the request timestamp is within 5 minutes of local time (consistent with §9.14 clock skew tolerance) and that the `nonce` has not been previously seen. Writers maintain a nonce deduplication cache with a 5-minute TTL, bounded at 10,000 entries with oldest-first eviction. Requests with expired timestamps or duplicate nonces are rejected.

4. **Rate limiting.** Writers MUST enforce per-DID rate limits on registration requests. Default limits: 1 registration per DID per hour, 10 updates per DID per hour. Context governance MAY configure stricter or more lenient limits. Rate-limited requests receive `ErrorCode::RATE_LIMITED` with a `Retry-After` hint.

5. **Earned capacity enforcement.** Writers SHOULD apply the earned capacity tier system (§9.3) to registration requests. New identities (tier 0) with minimal participation history receive lower registration priority or may be subject to additional verification requirements configured by the context's governance.

**Bootstrap / cold-start.** How agents find their first context:

- SDK ships with default bootstrap context IDs (configurable, analogous to browser CA lists or DNS root servers). These are not privileged — they are starting points.
- Apps can add domain-specific contexts with discovery tools (e.g., a cooking community registry, a translation services directory).
- On first identity creation, the SDK auto-queries default contexts with discovery tools and optionally self-registers (opt-out via configuration). Registration does not require MLS group membership.
- If all defaults are unavailable, agents fall back to direct DID resolution for known contacts and manual context ID sharing.

**Operation model.** Anyone can run a context with discovery tools:

- Creator sets governance: who can register, metadata requirements, moderation rules (via standard context governance, enforced by writers).
- Storage: structured metadata entries (~100-500 bytes per agent), not conversation history. Scale is limited only by relay storage capacity — the MLS group (writers) stays small regardless of registry size.
- No operator dependency: if one registry disappears, agents use others. DID + capabilities persist in the agent's DID document regardless.

**SDK unification.** The SDK provides a unified discovery API:

- Searches local contact index (cache of previously resolved DID documents — instant)
- Queries each known context (standard tool calls)
- Returns merged, deduplicated results ranked by relevance

**Privacy.** Registration is opt-in per context. Agents control what metadata they publish in each registry. Registration can be withdrawn at any time via `agent_deregister`. An agent can be registered in one context with full capabilities listed and in another with only a subset. DID document capabilities are controlled by the agent via DID document updates.

### 6.2.3 Broadcast Context Interactions

Outlet interfaces (§6.2) work with broadcast contexts. A broadcast context can expose outlets via the standard outlet interface mechanism — the context's governance mediates, the outlet schemas are declared, and calls are logged. Outlet invocation requires the invoker to hold the appropriate UCAN (`OutletQuery`/`OutletQueryAll` for Query outlets, `OutletCall`/`OutletCallAll` for Action outlets per §5.4.2.1), which is governed by the broadcast context's role system.

**Mixed-mode nesting (§5.13).** Child contexts may have a different `ContextMode` than their parents. A Broadcast child of Encrypted parents enables public read access to curated content from a private group. An Encrypted child of Broadcast parents enables private discussion among subscribers. Ceiling inheritance, eligibility enforcement, and lifecycle coupling operate identically regardless of mode.

**Discovery metadata.** When broadcast contexts register in contexts with discovery tools (§6.2.2B), the registration metadata includes the context mode. Agents searching for broadcast feeds can filter by mode. DID document `SCPBroadcastContext` service endpoints (§5.14.11) provide direct lookup for broadcast contexts without context queries.

## 6.3 The Human as Bridge

The human coordinates across their own contexts locally. Their local agent orchestration — unconstrained by the protocol — handles cross-context intelligence. For the human's own agents, the human remains the bridge — local coordination across their own contexts requires no network-level mechanism.

Two protocol-level mechanisms formalize cross-context relationships: outlet interfaces (§6.2) for asymmetric service-style interactions, and multi-parent child contexts (§5.13) for symmetric collaboration. Both require governance consent from all involved contexts. The human's local coordination handles everything that doesn't need to be on the network — and when a cross-context relationship should be visible, governed, and persistent, a multi-parent child context makes the bridge structural rather than implicit.

**Two-tier interaction model.** The protocol provides two tiers of cross-agent communication with different overhead appropriate to different risk profiles:

- **Shared contexts** (bilateral or multi-party) for lightweight, symmetric, low-ceremony communication. A message in a shared context is encrypt-send-decrypt with no per-message governance overhead. All the protocol's trust and encryption properties apply. This is the equivalent of a text message.
- **Outlet interfaces** for formal, structured, asymmetric cross-context data exchange. Full governance mediation on both sides, schema-declared data flow, audit logging, rate limiting, provenance attachment. This is the equivalent of an API call.

Agents use whichever tier fits the interaction. Lightweight coordination ("are you available?", "quick update") flows through shared contexts. Formal cross-context data queries flow through outlet interfaces. Both are governed; the difference is in ceremony and auditability per interaction.
