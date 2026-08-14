---
name: scpout047-ac8-layered-proof-reconciliation
description: SCP-OUT-047 AC8 amendment (598490f45) judged HONEST reconciliation, not scar-tissue — streaming-saga FFI recover proof relocated to layered form; blocking constraint is doubly-compounded and real
metadata:
  type: project
---

# SCP-OUT-047 AC8 amendment @ 598490f45 (feat/outlet-xctx-047-streaming-saga-ffi, HEAD d6abe0907) — HONEST RECONCILIATION, not scar-tissue

Alec amended AC8 after a coder STOPPED (couldn't build an FFI-through recover→Committed test). Judged: **honest reconciliation grounded in a real (compounded) constraint; substance proven elsewhere.** Only the test FORM changed; the guarantee is fully asserted somewhere real+live.

**Why:** The amendment relocated AC8's billed_count/exec-once/Committed proof from "single FFI-through-reconnect drive" to a layered proof: FFI-side = driver auth (3 rejection tests) + pipeline_wiring; runtime-side = `xctx_streaming_saga_truncated_close_ac7`.

**How to apply:** This is the canonical POSITIVE example of "amend the AC to a layered proof when a single end-to-end FFI test is genuinely non-constructible" — distinguishable from scar-tissue because ALL of: (a) the blocking constraint is real+load-bearing, (b) the substance is proven elsewhere against a REAL (not mock) fault, (c) every guarantee clause is asserted somewhere live.

## Verified facts
- **Constraint is DOUBLY compounded + real:**
  1. `spawn_actor_with_state` IS `pub(in crate::context)` (handle.rs:561, supervisor.rs:4368) — a DELIBERATE Class-S actor-state isolation boundary, independently relied on by a PRE-DATING concurrency test (supervisor.rs:32509 w/ explicit rationale comment :32506 "an external integration test cannot make a context resident"). Not an un-widened convenience.
  2. The FFI-registered outlet handler `OutletHandler = Arc<dyn Fn(Value)->Result<Value,String>>` (runtime.rs:147) is genuinely SINGLE-SHOT — cannot emit a multi-chunk prefix. Runtime's `PrefixThenBlockExecutor` (5 chunks then wedge) has NO FFI-registration analogue. So even widening spawn_actor_with_state would NOT yield a small seam — you'd also need a multi-chunk FFI executor the architecture deliberately omits, plus re-plumbing the whole runtime saga fixture across the crate boundary (which would relax the custody-key-bound resident-state isolation).
- **Substance genuinely proven:** `xctx_streaming_saga_truncated_close_ac7` (supervisor.rs:31756) is REAL: real supervisor+actor pair, durable ProtocolRepositorySagaJournal (not mock), 5-chunk prefix, keyless sweep→NeedsRepair (escrow HELD, invoked==1), key-bearing recover→invoked==1 (exec-once asserted TWICE), witness present, journal resolved (Committed), billed_count k∈1..=5, prefix manifest-root match, escrow settles at prefix, receipt verifies under target Active Signing Key.
- **FFI auth proven:** 3 live rejection tests e2e_bridge.rs:1946/1973/2008 (unhosted→ContextError channel-auth; unknown-saga→ContextError; hosted-non-invoker→SCP-PERM-3001 invoker gate) + pipeline_wiring `out047_pyo3_streaming_saga_recover_reaches_truncated_close` (asserts body reaches `drive_recover_truncated_close` + `identity_registry_contains`). Recover impl outlet_stream.rs:1515 resolves target custody key per-call (:1559). Test seam `insert_test_streaming_saga_entry` properly `#[cfg(any(test,feature=testing,allow_in_memory_custody))]`-gated (:1877), seeds only registry entry (invoker gate), NOT resident StreamCapture state. All cited tests live (none #[ignore]).

## Two NON-BLOCKING notes (raised, not blockers)
- **Provenance imprecision (PRE-EXISTING, not introduced by amendment):** AC6/AC8 note "as SCP-OUT-037 deferred [multi-chunk FFI streaming]" — 037's story text has ZERO mentions of defer/future/multi-chunk/single-shot/executor, and 037's own conformance AC says "collect 10 chunks" through each bridge (runtime-pump-relayed, NOT handler-yielded). The underlying architectural fact (single-shot handler) is code-verified, but the "037 deferred" citation is loose. Fix: cite where 037 established the single-shot handler, or drop "deferred" framing.
- **FFI-layer key-surfacing not structurally pinned:** pipeline_wiring pins auth + driver-reach but NOT the `resolve_context_signing_key` call; the "surfaces the key from custody" clause is proven only at runtime (AC7 receipt verifies under target key). Consider a structural assertion that recover body reaches key resolution.
