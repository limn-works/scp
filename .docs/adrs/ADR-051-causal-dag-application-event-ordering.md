# ADR-051: Causal-DAG Application-Event Ordering

**Status:** Accepted (model decided; implementation is a separate, forward program — see *Implementation and sequencing*).

**Date:** 2026-06-19

**Phase:** Phase 6 / event-log convergence

**Related:** ADR-011 (canonical `EventType` Merkle log + native↔WASM unification, phase-2.md), §9.8.3 / §9.8.5 (message ordering & sequence validation), §9.9.3 (equivocation detection), §23.16.1 (`ConsistencyCheckpoint` wire format), §23.16.8 (anti-spam / per-instance state wiped on import — velocity is local), §7.3.2 (participation records), §7.3.7 (consequence mechanisms), §19.7 (economic `SenderVelocity`), §9.3 (Sybil resistance — a deterrent, not a guarantee), ADR-031 (governance actions), ADR-049 (per-context actor).

## Context

The protocol's relay-equivocation defense (§9.9.3) rests on one property: **two honest members at the same log position MUST derive the same Merkle root.** For that detector to be valid, the canonical Merkle log may contain **only convergent events** — events every honest member appends identically and in the same order. The MLS-commit-ordered stream (governance, membership, lifecycle, role, access, attestation, provenance, economic *governance* actions, compromise recovery, app-binding) satisfies this; it is the canonical log today.

`MessageSent`, `ToolInvoked`, and the payment receipts `PaymentReceived`/`PaymentCaptureFailed` are appended only by their author/payee with no global order, so two honest members diverge at equal position. The ADR-011 unification therefore **excludes** them from the canonical log in the interim (local `ContextEvent`s) — which restores §9.9.3 soundness and is the prerequisite that lands first. **This ADR brings application events back into the canonical log as a convergent *order* — a causal DAG — giving tamper-evident message/tool history and a convergent `tool_invocation_count` (§7.3.2). It establishes convergent order and count, not convergent time.**

**On velocity and rate-derived consequences (the design that this ADR settles).** A velocity *rate* (count ÷ time) would need a convergent clock, and the protocol provides none: in a no-operator, transport-independent, offline-capable system there is no convergent, trustless wall clock (sender stamps forge; receiver-local time is per-receiver; beacon commits break zero-idle-cost; a relay clock is an untrusted oracle absent in P2P). More importantly, **it is not needed** — the apparent need rested on a false split between *executing* a consequence and *recording* it:

- **Rate-limiting is local flow control**, not a recorded consequence. Each member slows or drops what *it* is receiving, on its own clock — the live spam defense (zero-trust, immediate, transport-independent, P2P/offline). It is transient per-member intake management; there is nothing to record because it is not a governance state. This is the existing §23.16.8 local anti-spam state.
- **A suspension is a governance consequence**, where **executing it *is* recording it** — a convergent governance commit (ADR-031); the recorded agreed state *is* what every member enforces. There is no gap between doing it and writing it down.

So there is no "convergent velocity record" decoupled from enforcement to build — that decoupling was incoherent. A member observing sustained local throttling proposes the suspension as a governance action; it commits per the context's governance model; the commit is simultaneously its execution and its durable record. This is **automatic** (the SDK auto-proposes; the context's governance model commits it per its own declared rules — §7.3.7's "mechanical, not governance-discretion" is preserved: the *trigger* is mechanical and the *commit* is the context's pre-declared rule, no ad-hoc vote) and **convergent** (a commit) without any clock.

**Reconciliation with §9.8.3 / §9.8.5 (message ordering).** §9.8.3's *authoritative-ordering* paragraph models application-message order as a single-parent hash *chain* where "same parent ⇒ fork ⇒ equivocation." This ADR supersedes that for application events: their order is a **causal DAG**, where concurrent branches referencing a shared frontier are normal and deterministically linearized — not a fork. (§9.8.3's *delivery/display-reorder* reconstruction is unaffected.) §9.8.5's claim that the per-sender sequence "is included in the Merkle event log entry" no longer holds for application messages (interim: excluded; end-state: the DAG leaf carries causal head-references in place of a committer sequence). Both are amended to carry the interim/end-state qualification.

**Governing theorem:** a derived record is *automatic and convergent* iff its trigger **input** is convergent. Convergent order and count (this ADR) are convergent inputs; a member-derived wall-clock rate is not — so rate-limiting stays local and suspensions ride governance, where execution and record are one convergent act.

## Decision

Application events are ordered by a **causal Directed Acyclic Graph (DAG)** with deterministic linearization (§1–§4), made equivocation-safe over a frontier (§5). This yields convergent application-event order and count. There is no convergent clock; velocity and suspensions are handled per §6.

### 1. Causal references and head-reference validation

Every application event carries, **inside its signed/hashed leaf preimage**, the hashes of the DAG **heads** its author had observed. Edges point only backward (acyclic by construction). References are **normatively validated**:
- **Must resolve to a real, propagated leaf** (not merely a syntactically-valid hash).
- **Must include the full observed frontier** — an author cannot cherry-pick a subset to manufacture concurrency; causal position is non-discretionary.
- **Causally consistent with the author's own chain.**
- **Bounded buffering (anti-DoS):** an unresolved-reference event is buffered, not linearized, under a bounded pending size; a reference that does not backfill within a window is **rejected, not buffered indefinitely**.

A member's failure to reference an event it provably observed is an equivocation-class / suppression signal, not silently tolerated.

### 2. Deterministic linearization

Topological sort respecting causal edges; concurrent events ordered by ascending **canonical leaf hash** (`SHA-256(0x00 ‖ rmp_serde(Event))`, §25), constant-time compared. Same observed DAG ⇒ identical root.

The author-influenceable leaf-hash tie-break is made **security-irrelevant on the count axis by construction**: **must-include-frontier** (§1) prevents manufacturing concurrency, and the **per-author-aggregate rule (normative)** — every auto-derived fact/count keys on a per-author aggregate (a sender's own count), never on cross-author linear position — means reordering A vs B changes no count. (There is no convergent time axis to protect; rate-limiting is local — §6.)

### 3. No trusted sequencer

Order emerges from authors' signed causal references plus the deterministic rule. A relay can reorder/withhold *delivery* (delaying convergence, handled by §23.7) but cannot forge causal order — mandatory, since §9.9.3 exists to catch a lying relay.

### 4. Partition and offline tolerance

An offline author references its last-observed heads; on reconnection its events merge as concurrent branches and linearize deterministically. No send-time coordination. Convergence is eventual (the §23.7 sync model).

### 5. Equivocation test over the DAG frontier (§9.9.3 binding)

Two honest members can have observed different in-flight application events, so equal *raw count* need not mean equal leaf set — and §9.9.3 forbids loosening the equal-count test. Therefore the §9.9.3 `ConsistencyCheckpoint` (§23.16.1) gains a canonical **`frontierRoot`** field — a commitment to a canonically-sorted, deduplicated head-hash *set* — **inside the signed preimage** (a versioned `SCP-CHECKPOINT-V2`; the field must be authenticated or a relay forges it). The equivocation test compares `merkleRoot` **at equal `frontierRoot`** (two honest members who have observed the same DAG frontier must derive the same root), never at raw count. The totally-ordered commit prefix continues to use position directly.

### 6. Velocity is local flow control; suspensions are governance consequences

There is **no convergent velocity clock** (Context, above). Instead:

- **Rate-limiting = the local throttle.** Each member rate-limits incoming traffic on its *own* receiver clock — immediate, unforgeable by the sender, self-protective, per-member, transport-independent. This is the live spam defense and the §23.16.8 local anti-spam state; it is not a recorded consequence and needs no convergence.
- **A durable suspension = a governance consequence (ADR-031).** A member's SDK, on sustained local throttling of a sender, auto-proposes a `SuspendCapability` (or equivalent) governance action; it commits per the context's declared governance model. The commit is simultaneously the **execution** (every member enforces the agreed `write_suspended` state) and the **durable record** (the convergent governance leaf) — no clock, no execute/record split. Two honest scopings: **(i)** the durable record's *formation* depends on the context's governance model committing — in a SingleAdmin context whose admin is the abuser, or with a sub-quorum honest minority, no durable suspension forms, though each member's **local throttle still protects it**. The live defense is unconditional; the durable governance record is governance-gated, not convergent-by-construction in every configuration. **(ii)** The trigger (sustained local throttling) is a *proposer-side, non-convergent* observation; the commit rides the declared governance model (carrying that context's existing governance trust), but the trigger itself is proposer-trusted — not a convergent input other members can re-verify. The governance model gates the commit, which is where the trust already lives.
- **Convergent-triggered consequences** (governance warning-counts, role/lifecycle) auto-derive from the convergent log directly — their trigger is already convergent.
- **`tool_invocation_count` (§7.3.2)** is a convergent *count* over the DAG (this ADR); it never needed a clock. **Economic `SenderVelocity` pricing (§19.7)** is enforced at `authorize()` by the payer's own SDK against a local spending ledger — local and self-metered, also no clock.

## Consequences

**Positive.** `MessageSent`/`ToolInvoked`/`PaymentReceived` become convergent, Merkle-anchored, equivocation-detectable, frontier-ordered leaves — tamper-evident message/tool history and a convergent `tool_invocation_count`. The spam defense (local throttle) is zero-trust and unaffected by any relay or Sybil. The live spam defense (local throttle) is zero-trust and unconditional. A durable suspension is a governance commit where execution *is* the record — convergent **when the context's governance model commits it**; its formation therefore depends on that model (an abuser who is the sole admin, or a sub-quorum honest minority, yields no durable record, though the local throttle still protects each member). This is an honest accountability trade versus the prior soft, relay-vetoable clock record: stronger and more honest as a *live defense*, but not strictly superior on the *durable-accountability* axis (where governance will not act, no durable rate-abuse record forms — consistent with the protocol's no-operator, governance-based nature). No soft-signal clock, no config; the model rests only on what the protocol can guarantee (cryptographic commit ordering + the local throttle).

**Costs / trade-offs.** Causal metadata (head-set) per application event + a `frontierRoot` on checkpoints; convergence of message/tool *order* is eventual (the §23.7 sync model); a velocity-driven suspension forms at governance-commit latency rather than instantly (the local throttle covers the live window); implementation breadth spans the messaging path, the event-log substrate, the `ConsistencyCheckpoint` structure (§23.16.1), §9.8.3/§9.8.5 ordering text, and all FFI/WASM bridges.

## Alternatives considered

- **A convergent "velocity clock" (REJECTED — the central decision).** Every construction was tried and rejected: a member-population median (rests on a Sybil-paddable honest majority); a multi-vantage / receiver-quorum median bounded by sender/relay stamps (the sender/relay floor is an attacker lever in both directions — it can raise the value to dodge a window, and an author can future-date its own stamp to force "inconsistent → no record"); a relay ingest clock (untrusted oracle, absent in P2P); beacon commits (break zero-idle-cost). Beyond being hard, a convergent velocity record was **unnecessary and incoherent**: it presumed a split between executing a consequence and recording it. Rate-limiting is local flow control (not a record); a suspension is a governance commit (execution *is* the record). So there is nothing for a clock to build.
- **Consensus-outcome routed through an ad-hoc vote (REJECTED).** Suspensions ride the context's *pre-declared* governance model (mechanical), not an ad-hoc discretionary vote — preserving §7.3.7's "automatic, not governance-discretion."
- **Relay-assigned global sequence (REJECTED).** Trusted ordering authority — self-defeating for §9.9.3; incompatible with offline sends.
- **Count-over-causal-window as a velocity proxy (REJECTED).** Measures relative share (anti-dominance), not absolute rate; and the absolute-rate durable record is itself not wanted (above).
- **Per-context "convergent-velocity" config opt-in (REJECTED).** "Make it configurable" is not an answer to "is this safe"; one canonical behavior.

## Security requirements (normative for the implementation program)

1. **Head-reference validation (§1):** must-resolve-to-a-propagated-leaf, must-include-frontier, author-causal-consistency, refs inside the signed leaf; bounded buffering (max pending; reject refs that do not backfill within the window).
2. **Frontier-bound equivocation test (§5):** `ConsistencyCheckpoint` gains an authenticated `frontierRoot` (sorted, deduplicated head-hash set) inside the `SCP-CHECKPOINT-V2` signed preimage; the test is equal-`frontierRoot`/equal-`merkleRoot`, never raw count.
3. **Per-author-aggregate rule (§2):** convergent facts/counts key on per-author aggregates, never cross-author linear position; enforced by §25 conformance, not prose.
4. **Velocity stays local; suspensions are governance commits (§6):** rate-limiting is the per-member local throttle (never a canonical leaf); a durable suspension is a governance action whose commit is its execution and its record (no clock, no separate convergent velocity record).
5. **Cross-implementation conformance (§25):** KAT vectors MUST pin (a) DAG linearization including a partial-observation snapshot (some heads resolved, some buffered); (b) `frontierRoot` bytes for an unsorted-input / duplicate-after-dedup head set; (c) `tool_invocation_count` derivation over a fixed DAG. A happy-path triple is insufficient.
6. **Interim anchoring is mechanical, not prose:** while application events are interim-excluded (step 1), per-author facts (`tool_invocation_count`, payment provenance) carry a machine-readable **`anchored` boolean field** — covered by the existing signature — so consuming subsystems mechanically distinguish anchored (convergent under this ADR) from unanchored (interim, local) facts; a §25 conformance vector asserts a consumer rejects/down-weights `anchored=false`.

## Implementation and sequencing

1. **Unification (prerequisite, lands first — the original goal).** The canonical log carries convergent (commit-ordered) events only; `MessageSent`/`ToolInvoked`/`PaymentReceived` are excluded, surfaced as local `ContextEvent`s. §9.9.3 is sound over the convergent subset; this **unblocks #1535** (catch-up consistency proof). Velocity is the local throttle; convergent-triggered consequences auto-derive and are durable now; per-author facts carry `anchored=false`.

   **Interim posture (normative):** `tool_invocation_count` and payment provenance carry no Merkle proof until this ADR's DAG lands and MUST surface `anchored=false`; the local throttle is the spam defense throughout.

2. **Causal-DAG application-event ordering (this ADR).** Application events gain validated causal references and re-enter the canonical log as convergent, frontier-ordered leaves; `tool_invocation_count` becomes convergent (`anchored=true`); message/tool history becomes tamper-evident and equivocation-detectable. This is its own forward program, sequenced after step 1. Velocity remains local and suspensions remain governance commits throughout — neither depends on this step.

Until step 2 lands, every affected guarantee is qualified at its source so the interim is a documented waypoint, never a silent gap.
