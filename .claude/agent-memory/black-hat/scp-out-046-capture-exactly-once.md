---
name: scp-out-046-capture-exactly-once
description: SCP-OUT-046 streaming xctx settle capture exactly-once — pass-4 verdict, two-layer model, residuals
metadata:
  type: project
---

# SCP-OUT-046 streaming xctx settle — capture exactly-once (pass-4)

Branch feat/outlet-xctx-046-seal-fsm. Fix commit 2c3b2408c.

**Verdict: concurrent double-capture CLOSED. Two residuals, both design-accepted / pre-existing, not introduced by the fix.**

Key files:
- `crates/scp-runtime/src/context/outlets_helpers.rs` — `settle_outlet_stream`
  - pre-commit read `~1711-1725` (reads `xctx_committed_stream_outputs[sid].settled` BEFORE commit; returns `AlreadySettled`)
  - first-settle atomic money+flag closure `~1889-1930` (`commit_class_s_keep`)
  - `authorize_and_capture_stream_billed` `2134` — `idempotency_key: request_id` set ONLY on authorize metadata (2145), NOT on capture
- `crates/scp-runtime/src/context/actor/handlers/outlets.rs:433` — AlreadySettled → applied:true, ok_unmutated (all 3 variants matched, no `_ =>`)
- `crates/scp-runtime/src/context/actor/class_s.rs:2792-2802` — `commit_class_s_keep` NO rollback (in-mem mutation kept on persist Err)
- `crates/scp-runtime/src/context/actor/handlers/saga.rs:2513` — `rebuild_stream_settlement` copies `committed.request_id` verbatim (Layer 2 key stable)
- `crates/scp-runtime/src/economy/adapter.rs:165` — idempotency_key advisory only; NO runtime capture-dedup ledger

**Residual R1 (Layer 2 trust): crash-window dedup delegated entirely to external adapter.** No runtime capture-dedup ledger. idempotency_key passed only to `authorize`, not `capture`. Exactly-once across crash requires adapter to (a) dedup authorize on key AND (b) be capture-idempotent per auth_id. Trait mandates NEITHER (doc "prevent duplicate authorization" = advisory). If injected adapter dedup is best-effort/absent → real double-bill, bounded to 1 re-capture. Hardening: mandate idempotency in trait contract or add runtime dedup ledger keyed by request_id.

**Residual R2 (lost-bill on capture failure): settled flag set BEFORE + independent of capture success.** First settle: closure sets settled=true (persist), capture runs after. If capture FAILS transiently → durable settled=true + PaymentCaptureFailed audit event, and ANY future re-settle short-circuits AlreadySettled → NEVER re-captures. Transient capture failure = permanent un-bill (operator absorbs). Design-accepted per H8 (audit-trail reconciliation, not auto-retry), invoker-favoring.

Confirmed sound: actor serialization (no intra/inter-settle TOCTOU even across awaits), KEEP never rolls back settled, gen-mismatch xctx defers entirely (no capture, recovery completes w/ same request_id), reconcile sweep is invoker-favoring (over-refund not over-charge).
