---
name: adr051-causal-dag-review
description: ADR-051 causal-DAG application-event ordering + convergent median clock — architecture review findings (interim→end-state staging, EventType convergence taxonomy)
metadata:
  type: project
---

ADR-051 (`.docs/adrs/ADR-051-causal-dag-application-event-ordering.md`, accepted 2026-06-18) makes application events convergent: causal-DAG ordering (deterministic linearization by canonical leaf hash) + median-of-member-receive-times clock carried on the §9.9.3 `ConsistencyCheckpoint`. Two-step program: step 1 = ADR-011 unification (app events excluded, local-only); step 2 = ADR-051 (DAG + frontierRoot + median clock, lifts all interim qualifications).

**Why:** §9.9.3 relay-equivocation detection requires the canonical Merkle log contain ONLY convergent events (two honest members at equal position derive equal root). `MessageSent`/`ToolInvoked`/`PaymentReceived` are per-author with no global order → non-convergent → were stranding `tool_invocation_count` (§7.3.2), economic velocity (§19.7), velocity-consequences (§7.3.7).

**How to apply when reviewing this area:**
- The convergence governing theorem: a derived record is automatic AND convergent iff its trigger input (count + time) is convergent.
- `frontierRoot` on §23.16.1 ConsistencyCheckpoint is a SIGNED wire field — adding it breaks the `SCP-CHECKPOINT-V1:` signature preimage (currently 7 fields, fixed order). ADR scopes it as step-2 work; interim wire format unaffected. This is clean.
- EventType is 75 variants (Rust `crates/scp-event-log/src/lib.rs` AND phase-2.md listing both = 75). PR #1827 commit msg said "76" — that was a miscount. §25 vector-32 76→75 fix is the only place the count appears; correct.

**Open findings from my review (CHANGES-NEEDED):**
1. §9.8.5 NOT amended despite ADR lines 21+90 claiming "§9.8.3/§9.8.5 are amended." §9.8.5 still says per-sender sequence "included in...the Merkle event log entry" — false for app messages in both interim (excluded) and end-state (DAG leaf carries head-refs in place of sequence, per the §7.3.1 amendment).
2. §6 cross-context tool saga records `ToolInvoked` (B) + `CrossContextToolInvoked` (A) as durable SagaId-idempotent CANONICAL leaves; B's `tool_invoked_event_id` is signed into `CrossContextToolReceipt` non-repudiation preimage. ADR-011 amendment exclusion-taxonomy §2 blanket-classifies ALL `ToolInvoked` as non-convergent per-author → contradiction. Cross-context ToolInvoked is commit-ordered/convergent (saga Commit phase), NOT the ADR-051 case. `CrossContextToolInvoked` not even in the taxonomy. Spec-only today (receipt unimplemented in code) so no live regression. ToolInvoked has 2 emission paths w/ different convergence.
3. §7.3.7 "Tool invocation rate exceeds threshold → tool access revoked" left UNqualified while the adjacent "Message velocity" line got the ADR-051 note. Tool-rate is the same per-author rate (count÷time) needing the median clock; ADR §7 enumerates only the message-velocity participation-suspension as the clock consumer, omits tool-rate. Both a spec gap (the line) and an ADR §7 completeness gap (second clock consumer).

**Correctly out of scope (verified):** §9.3 earned-capacity rates (`initial_message_rate`/`initial_tool_invocation_rate`) are SDK-LOCAL self-meter ("enforced at the SDK level", line 229) — same category as economic SenderVelocity (payer self-meters at authorize()). Not a convergent durable record, correctly unreconciled.

**Design quality:** all-current-members deterministic cut-closure + liveness-fallback-to-local-throttle is sound as a permanent design (no-DOA): closure is a pure predicate over collected signed checkpoints (observation-order-independent), unclosable cut → no durable consequence + local fallback, never a partial/observed-subset median (the false-equivocation source). Honest-majority-of-attesters trust bound is explicitly weaker than §9.9.3's 2-honest and scoped to a soft control w/ local backstop + §9.3 Sybil resistance. Sound. Checkpoint reuse (vs parallel attestation stream) is the right call — rejected alternative (optional per-event attestations) is withholding-manipulable; mandatory periodic checkpoint removes the selective-omission lever.
