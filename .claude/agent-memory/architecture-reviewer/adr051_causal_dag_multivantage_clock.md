---
name: adr051-causal-dag-multivantage-clock
description: ADR-051 application-event ordering — causal DAG + multi-vantage median clock; rejections, carve-outs, interim/end-state split
metadata:
  type: project
---

ADR-051 (`.docs/adrs/ADR-051-causal-dag-application-event-ordering.md`, Accepted 2026-06-19) makes per-author application events (`MessageSent`/`ToolInvoked`/`PaymentReceived`/`PaymentCaptureFailed`) convergent so they re-enter the canonical RFC-6962 Merkle log. Builds on the ADR-011 amendment (`[[eventlog-unification-adr011]]`).

**Model:** causal DAG (events carry signed head-refs to observed frontier; must-resolve + must-include-frontier validated) + deterministic linearization (topo sort, tie-break ascending canonical leaf hash) + frontier-bound equivocation test (`ConsistencyCheckpoint` gains authenticated `frontierRoot` in `SCP-CHECKPOINT-V2`; compare root at equal frontier, never raw count) + multi-vantage median clock (median of signed sender/node/relay/receiver-quorum stamps, **anchored on receiver quorum**, clamped >= max(sender, relay-ingest) lower bound).

**Why each rejection is sound (do not re-litigate):**
- Single-party clocks: sender forges, receiver-local non-convergent, relay-sole = timing oracle + breaks P2P, beacon = breaks zero-idle-cost.
- Member-population median: rests on honest-majority of Sybil-paddable population (attestation only PRICES Sybils per §9.3, doesn't guarantee majority); no independent cross-check. Multi-vantage replaces it — 4 independent trust domains w/ opposing incentives.
- Relay global sequence / BFT / consensus-outcome / count-proxy / config-opt-in: all rejected, each soundly.

**Explicitly a robust SOFT signal, not a cryptographic guarantee** — residual is receiver-Sybil-majority claiming LATE receipt; backstopped by the zero-trust local throttle (§23.16.4 anti-spam state, retained). "No honest-majority-of-single-population, no attestation-guarantee dependency, no config."

**Small-context floor REMOVED and that is sound:** receiver-stamp spread is set by network latency + online/offline status, NOT member count — construction is size-independent, so a floor would be arbitrary and contradict the one-canonical-behavior stance.

**Key carve-out (correct, not a contradiction):** §6 cross-context tool-call saga records `ToolInvoked`/`CrossContextToolInvoked` inside the MLS-Commit phase — commit-ordered, convergent, SagaId-idempotent append, staged deterministic `recorded_timestamp_ms` (NOT per-author wall clock). It is NOT in the per-author exclusion. The exclusion is the intra-context per-author emission only.

**Load-bearing clock consumer = participation-suspension (§7.3.7) only.** `tool_invocation_count` (§7.3.2) needs convergent DAG count, NOT clock. Economic `SenderVelocity` (§19.7) enforced at authorize() by payer's local ledger — clock not load-bearing. ADR is careful not to over-claim clock reach.

**EventType count:** doc corrected 76→75 in §25 test-vectors.md to match actual `crates/scp-event-log/src/lib.rs` enum (verified 75). Docs-only diff; no code touched.

**Implementation is a separate forward program**, sequenced AFTER ADR-011 unification. Interim: app events are local `ContextEvent`s, velocity-suspension is per-member/non-durable/MUST-NOT-be-relied-on, anchored=false flag on interim per-author facts.
