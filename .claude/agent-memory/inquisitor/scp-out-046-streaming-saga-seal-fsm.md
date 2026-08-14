---
name: scp-out-046-streaming-saga-seal-fsm
description: Verdict on SCP-OUT-046 streaming-saga seal-phase FSM premises — all sound, architecture-forced, not scar tissue. Do not re-litigate the custody split.
metadata:
  type: project
---

# SCP-OUT-046 streaming-saga seal-phase FSM — premise interrogation (2026-07-15)

Verdict: SOUND. Every load-bearing premise traces to a settled Accepted upstream artifact.
Branch feat/outlet-xctx-046-seal-fsm touched NO upstream artifact (ADR-049/ADR-061/specs
unchanged; only outlet.json status→done) — pure downstream impl, no artifact-flow inversion.

**Why:** future passes will see the "custody split → NeedsRepair-without-key" and be tempted
to call it a DOA gap. It is not. Re-derived from current code, it is architecture-forced.

**How to apply — the custody split is NOT scar tissue:**
- ADR-049 invariant: the actor/runtime holds NO custody signing key. Confirmed at
  supervisor.rs:657-668 — the UNARY saga FSM ALSO takes `target_signing_key` caller-supplied,
  held in-memory for the FSM lifetime, zeroized on drop. Streaming applies the identical rule.
- Both `build_signed_receipt` (unary) and `build_signed_stream_receipt` (streaming, saga.rs:2806)
  take `target_signing_key: &SigningKeyBytes` as a per-call PARAMETER — key flows through, not held.
- Keyless crash-recovery is consistent across unary and streaming: neither forges a signature.
  Unary `redrive_xctx_commit_in_progress` re-drives the *idempotent* Commit-B (re-emits the
  already-stored receipt, no key). Streaming `recover_streaming_committing_entry` (supervisor.rs:7779)
  sends read-only StreamSettleCheckWitness: present→Committed; absent→NeedsRepair + escrow HELD.
- NeedsRepair-hold-escrow-until-operator-repair is spec-sanctioned (§6.2.4 "NeedsRepair reservation
  semantics" + ADR-049 §3a: slot released, escrow held). Auto-sealing without the key would require
  autonomous custody = ADR-049 violation + a nullifier (CLAUDE.md forbids). NeedsRepair is the honest
  fail-closed state; absence is detectable, a forged signature would lie.
- Key-bearing `recover_streaming_saga_truncated_close` (supervisor.rs:6818) DOES seal+sign the
  truncated prefix per ADR-061:48 — reachable only by unit test today because the whole streaming-saga
  FFI (incl. operator key re-supply) is legitimately deferred to SCP-OUT-047 (ADR-049 §3a ordering
  constraint + per-set-gating prerequisite). Mirrors unary saga recovery being "inert in production"
  until its FFI producer ships (ADR-049 §3a:70) — established precedent, not a new gap.

**Other premises (all SOUND):**
- No-Prepare-A: streaming economy is §5.4.5 per-chunk credit/escrow metered in B, not a caller-side
  per-invocation cost reservation. Anti-griefing bound = B-side OriginAdmissionTracker + pump-semaphore
  + node-wide max_concurrent_outlet_stream_pumps (ADR-049 §3a(b): correct instrument for long-lived
  off-mailbox pumps; per-set gate is the WRONG instrument). Not a §6.2.4 symmetry break.
- Off-mailbox settlement: ADR-049 actor model is the root cause, not a coupling to refactor. Seal task
  reaches actor Class-S state the only sanctioned way — a mailbox message (CommitBStreamSettle →
  settle_outlet_stream_via_actor, invoke.rs:5172). Correct discipline.
- Dual-sink-off: the Phase-1 extract (open_outlet_stream_phase1) made settlement_sink AND
  invoked_event_sink explicit per-caller decisions, REMOVING the accidental `.or(durable_invoked_sink)`
  baked-in default. A de-conflation, the opposite of scar tissue.
- Seal-owns-settlement: REUSES settle_outlet_stream_via_actor + StreamSettlement (same primitive as
  same-context), building the settlement from a durable ledger. The durable-ledger difference is
  crash-safety-forced (reservation object can't cross the mailbox turn). Real frontier.root() at seal
  (saga.rs:2553), never [0u8;32]. No reimplementation, no nullifier.

**One QUESTION worth carrying to 047 (not a blocker):** plan line 45 already flags that SCP-OUT-047
must enumerate the 3-bridge streaming FFI exports + SDK wrappers + capability-matrix rows AND the
channel-authenticated caller_did binding (ADR-049 §3a "Forward obligation"). Confirm 047's story
carries the caller-side auth binding before the FFI surface ships — else artifact-flow gap in 047.
