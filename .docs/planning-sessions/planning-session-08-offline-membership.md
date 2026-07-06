# SCP Planning Session 08 — Offline Membership: the KeyPackage-Exhaustion Structural Fix

**Date:** July 4, 2026
**Scope:** Resolve the design question ADR-057 deferred under the (mis)label "Presence ADR": what genuinely remains open about long-absence membership, and what to do about it. Four decisions locked (D1–D4).
**Status:** Decided — awaiting execution (queued behind the ADR-057 in-flight slices; see the corrective-slice list in `.docs/adrs/ADR-057-in-browser-client-over-shared-mls.md`).
**Provenance:** spec §9.6.2 KeyPackage lifecycle + §9.9.2 suppression detection (`.docs/specs/09-security-model.md`), §23 sync/offline strategy incl. §23.4.1 Welcome fast-forward and §23.5.2 Tier-3 reset (`.docs/specs/23-sync-and-offline-strategy.md`), §5.6 membership lifecycle + §5.4 presence-only state (`.docs/specs/05-contexts.md`), §10.8.1 multi-device + §10.9 presence-as-tool (`.docs/specs/10-infrastructure-and-self-hosting.md`), ADR-029 (`.docs/adrs/phase-6.md`), ADR-057 Consequences (deferred presence bullet). RFC 9420 §10 (last-resort KeyPackages).

## How this question was re-scoped

ADR-057 deferred a "Presence ADR" for the browser client. Two corrections were made in this session before any decision:

1. **The problem is not browser-specific.** Membership decay during absence applies to every non-always-on participant — desktop apps, phones, agents, browser tabs — differing only in absence duration. The browser is the extreme (guaranteed-ephemeral) end of the spectrum, which is merely where it got noticed. Any fix is protocol-level, with per-client-class profiles at most.

2. **The problem space is mostly already decided.** A corpus sweep confirmed five of six sub-problems are settled, shipped stances — not open questions:
   - §9.9.2 heartbeats are **relay-suppression detection only**, never a membership-liveness obligation. Members have zero idle obligations: "Standing contexts have zero idle cost. No keepalives, no heartbeats, no periodic key rotation (MLS key updates happen on message send, not on a timer)" (`05-contexts.md:1019`).
   - **Absence never evicts.** Membership removal is exclusively governance `RemoveMember`, self-`leave`, failed-join rollback, or child-context eligibility loss. There is no eviction-after-N-missed-anything anywhere, deliberately.
   - **Reconnection/catch-up is fully specified and shipped** (§23 three-tier model, six-phase protocol, Tier-3 per-member reset preserving DID/role/history, RFC-6962 consistency-proof catch-up; ADR-029).
   - **Delegated keep-alive was decided away**, not overlooked: "Presence, typing indicators, live collaboration: these are tool-level or context-level capabilities, not protocol primitives" (§10.9). Nothing needs keeping alive because idle costs nothing and silence never evicts.
   - **Multi-device (§10.8.1)** already lets any online device of a DID service that DID's liveness (shared per-DID sender/access keys; per-device leaves and KeyPackage pools).
   - Terminology: "presence" already names an unrelated membership state — the presence-only member of §5.4 (read+write revoked, governance-visible). The deferred work must not be called "Presence."

What survives as genuinely open is one structural defect and two small additions — decided below.

## The structural defect (D1's subject)

Both paths by which an absent member is added or recovered **require a live pre-published KeyPackage**:
- being added to a new context (§9.6.2 single-use KP pool, buffer 10 / replenish at 5),
- Welcome-based fast-forward catch-up (§23.4.1 step 3),
- Tier-3 (>7 days) reset re-join (§23.5.2 step 2).

Replenishment requires being online. KeyPackages are single-use and are consumed by *other people's actions* (adds) while the owner is away. SCP defines no reusable fallback. Therefore a sufficiently-added, sufficiently-offline member's pool drains to zero, at which point they are **un-re-addable and un-recoverable-past-Tier-2 until they come online and republish** — and if their absence already exceeds 7 days when this happens, the recovery path itself is the thing that's broken.

The only mitigation the current design offers is an always-on device of the same DID that keeps the pool replenished. **Ruling: relying on that is absurd as a baseline** — it presumes most users run always-on personal infrastructure enrolled in every context they care about, which contradicts the phone-only reality of most users and cuts against the protocol-requires-no-operator tenet in spirit (per-user always-on hardware is a de facto per-user operator requirement). The defect is structural, and the fix must work for a phone-only user with zero infrastructure.

## Decisions

**D1 — Last-resort KeyPackage (the structural fix).** Adopt RFC 9420 §10's explicitly-permitted last-resort KeyPackage: each identity (per device) maintains, alongside the single-use pool, one designated **reusable** KeyPackage. Relays serve it **only when the single-use pool is empty** (serve-order semantics are normative: single-use first, always). Joins performed against a last-resort KP carry a documented forward-secrecy reduction — compromise of the last-resort KP's private key exposes the Welcome secrets of every group joined through it during its service window — which is **healed by the member's next Update on return**, and the member MUST mint a fresh last-resort KP and replenish the single-use pool on reconnection (fold into §23's six-phase reconnection as part of the existing forced-Update phase). This makes every member permanently re-addable and keeps Tier-3 recovery viable at any absence length, with no infrastructure assumption. Spec targets: §9.6.2 (KP lifecycle + the new serve-order and rotation rules), §23.4.1/§23.5.2 (recovery paths may consume it), threat-model note in §9 for the FS window.

**D2 — Presumed-offline peer state.** Introduce a first-class, consumable peer-liveness classification: uniform silence across **all** of a sender's relays = *presumed offline* (benign absence); cross-relay divergence = *suppression suspected* (existing §9.9.2 semantics, unchanged). Today the machinery produces only the suppression signal and leaves uniform silence unclassified; downstream consumers (SDK surface, UX, D3's policy) get a defined state instead of inferring one. This stays compatible with the presence-is-a-tool stance: it is a transport-level classification exposed to clients, not a protocol-level presence primitive broadcast to peers.

**D3 — Opt-in absence-hygiene governance policy.** The unconditional default remains exactly as it is: **absence never evicts**. Add an optional, per-context governance parameter (legible pre-join like all context parameters, §5) by which a context may enable *auto-proposal* of removal after N days of a member's absence — a governance **proposal**, subject to the context's normal removal governance, never an automatic removal. Contexts that want membership hygiene (e.g. workspaces pruning ghosts) can opt in; everything else is untouched. Ruled "useful and reasonable."

**D4 — No primary-device formalization.** Do not formalize an always-on/primary device (or any delegate) as the answer to absence — that would enshrine the assumption D1 exists to eliminate. Multi-device remains what §10.8.1 makes it: a capability. The attenuated keep-alive delegate idea is dead: heartbeats need not be delegated (no idle obligation exists — see the sweep), Updates cannot be soundly delegated (holding the leaf key = full impersonation; pre-signed Updates defeat PCS's purpose), and KeyPackage availability is solved key-lessly by D1 (a last-resort KP is public material — anyone can *serve* it; no delegate needed to *mint* it).

## Execution notes

- Deliverables: spec amendments (§9.6.2, §23, §9.9.2-adjacent for D2, §5 context-parameter for D3) + one ADR recording D1–D4 with the rejected alternatives (always-on-device reliance, delegated keep-alive, unconditional absence-decay). Then implementation slices (KP pool + relay serve-order + reconnection rotation; the D2 classification; the D3 parameter through governance).
- Naming: the ADR/spec language uses **offline membership / absence**, not "presence" (§5.4 collision).
- Sequencing: queued behind the in-flight ADR-057 corrective slices (#1965 → #1975 → #1976 → #1980 → test stack → Slice 3/4); this artifact exists so the rulings survive until then.
