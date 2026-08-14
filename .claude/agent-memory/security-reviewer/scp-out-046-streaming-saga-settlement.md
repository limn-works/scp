---
name: scp-out-046-streaming-saga-settlement
description: SCP-OUT-046 xctx streaming-saga settlement-atomicity fix — keyless crash recovery moves money, redacting SigningKeyBytes Debug. Pass-2 verified clean.
metadata:
  type: project
---

# SCP-OUT-046 streaming-saga settlement atomicity (feat/outlet-xctx-046-seal-fsm)

Fix delta `18f6fd11c..HEAD` (4 commits). Pass-2 security re-review 2026-07-15: NO blocking findings; the earlier settlement-reconcile MEDIUM is CLOSED.

**Why:** xctx streaming saga runs with `settlement_sink = None` — it has NO `stream_reservations` reconcile net (unlike same-context pump). A crash/eviction in the seal→settle window left the durable escrow debit stranded (no refund, no capture, no counter release). Old code logged "crash-recovery sweep reconciles the durable reserve" but no such reconcile existed for xctx — overstated.

**The fix (durable `settled` flag + keyless completion):**
- Seal handler (`commit_b_stream_first_settle`) inserts witness `CommittedStreamingOutletInvocation` with `settled=false` in the SAME Class-S persist that removes the prepared slot, BEFORE the off-mailbox money move. Witness now carries all settlement-rebuild fields (reserved/billed/refund/request_id/ucan_cid/cost_per_chunk/amount_cumulative_reserved/economic_policy) copied from prepared slot.
- Money move (`settle_outlet_stream` under `witness_saga_id: Some`) flips `settled=true` atomically with refund+release under the same Class-S persist.
- Generation-mismatch / no-actor with `witness_saga_id: Some` → DEFER ENTIRELY (no capture, `applied=false`); witness stays unsettled; seal task leaves journal `Committing`.
- Keyless recovery sweep (`complete_unsettled_streaming_saga`): present && !settled → rebuild `StreamSettlement` from witness, apply against B's CURRENT generation. Settlement is pure budget/counter ops — needs NO signing key (receipt was already signed at seal). Exactly-once via `settled` flag.

**Security verification (all PASS):**
1. Keyless money move is SAFE — witness only inserted by authentic seal handler (requires target signing key + produces signed receipt); recovery gates on `status.present`; amounts fixed at seal from durable frontier, not recovery-time controllable. No nullifier/priv-esc — no signature needed for money ops.
2. `SigningKeyBytes` redacting Debug (commands.rs ~616): prints `SigningKeyBytes("<redacted>")`, no byte leak; doesn't touch `Zeroizing` field or Drop — zeroization intact.
3. Widened reply types (`StreamWitnessRecoveryStatus`, `StreamSettleApplication`, `StreamSettlement`) carry NO keys/secrets — only DIDs (public), amounts, request_id, ucan_cid (a CID not the token), economic policy. Derive Debug but NEVER `{:?}`-logged (all tracing logs saga_id/err/context_id/request_id-hex/generation only).
4. invoke.rs ~5175 comment no longer overstates — now "journal left Committing; crash-recovery completes refund+counter release from durable witness." Fail-closed preserved: no under-charge / free-exec / key leak.
5. Auth gates (is_member + established interface + §7.3.8 caveat) untouched — those are upstream in acceptance path, not settlement/recovery.

**Observations (non-blocking):** (a) `debug_assert!(billed <= reserved)` at seal only fires in debug builds, but `billed <= reserved` is guaranteed by escrow credit ceiling — proportionate. (b) If target context NEVER respawns, invoker escrow stays fully held indefinitely (refund never credited) — conservative fail-closed direction, matches pre-existing witness-absent NeedsRepair semantics, not a regression.

**GOTCHA reconfirmed:** `cd /Users/alec/Developer/limn/scp` in Bash hits MAIN worktree (branch main, different HEAD) — git diff/grep there give bogus results. Use `git show`/`git diff` WITHOUT cd (stays in agent worktree) or the full worktree path.
