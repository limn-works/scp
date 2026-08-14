---
name: scp-2203-optionB-cancel-fetch-then-sign
description: Design review of #2203 Option-B cross-context browser OutletCancel (fetch-then-sign); verified cancel-construction properties in scp-runtime/protocol outlets
metadata:
  type: project
---

# #2203 Option-B browser OutletCancel (fetch-then-sign) — DESIGN review (no code yet)

VERDICT: cryptographically SOUND to proceed to human sign-off. No blockers. Findings all defense-in-depth/impl-phase.

Proposal: remote/browser invoker fetches node's live emission cursor over MLS control channel (echo request_id), signs SCP-OUTLET-CANCEL-V1 in-tab over that cursor, routes fully-formed OutletStreamCancel → node `apply_outlet_cancel_verbatim`. AMENDS §5.4.5 "Co-located vs. remote receiver" carve-out (:517-519) which currently says remote invoker MUST NOT sign OutletCancel (Option-A only: StreamGap + credit-stall/timeout). Option-B = acceleration layer over Option-A floor, never replacement.

## Verified construction facts (origin/main, all line#s origin/main)
- `apply_outlet_cancel_verbatim` (dispatch.rs:1179, `#[allow(dead_code)]`, the Option-B entrypoint): reads guard.credit.identity() triple + invoker_pk; cross-checks `cancel.next_seq == guard.next_emission_seq` → else CursorAdvanced NO mutation (line 1193); verify_cancel_signature under pinned invoker_pk+triple → else SignatureInvalid NO mutation; record_cancel; notify. The cross-check reads the LIVE cursor at apply time, NOT the fetched hint → a lied/stale cursor can only yield CursorAdvanced or coincidentally-correct, NEVER a wrong accepted cancel_ack_seq.
- Cancel preimage (scp-protocol/stream.rs:770): SHA256(SCP-OUTLET-CANCEL-V1: || len32 ctx || ctx || len32 outlet || outlet || request_id[16] || next_seq_be[8] || caveats_binding[32]); Ed25519 verify_strict. Prefix-free, binds request_id + triple. stream_epoch deliberately NOT in preimage (same rationale as chunk-sig: request_id UUIDv7 uniqueness + caveats_binding pinning). Q5 SOUND.
- record_cancel (runtime stream.rs:1066): FIRST-WRITER-WINS — only Active→Pending; replay is no-op; cancel_ack_at (timer origin) pinned at first arrival → replay does NOT re-arm timer. cancel_ack_seq pinned. Q3(b) SOUND.
- CURSOR advances ONLY in pump Forward arm (dispatch.rs:3034/3079) after `apply_stream_chunk_gate` (invoke.rs:2572). Gate: terminal (End / Error{terminal:true}) BYPASS credit (line 2578) but BREAK the loop (terminate). Data AND Progress both call try_consume (line 2601) → Stall+freeze on no-credit. is_billable=Data-only. So NO non-terminal chunk advances cursor without consuming credit; only terminals do, and they terminate. Withhold credit → outstanding credit is bounded (min(credit_window,max_calls)) and only decreases → cursor freezes in bounded steps → equality converges; else Option-A floor (credit-stall 30s / cancel-ack 5s / timeout) → terminal → settle. Q2 livelock FULLY terminates.
- CancelError::CursorAdvanced → SLUG_TRANSPORT_RATE_LIMITED / CODE_TRANSPORT_FAULT = SCP-OUTLET-6160 range (Transport, WithBackoff 1s..30s). Design's "6160 retryable backoff" is ACCURATE.

## FINDINGS (none blocking)
- MEDIUM defense-in-depth: `apply_outlet_cancel_verbatim` does NOT self-check `cancel.request_id == self.request_id` (confirmed: grep of 1179-1218 = no request_id compare). request_id binding in the preimage then relies SOLELY on correct node routing-by-request_id. For two streams sharing (context_id,outlet_id,caveats_binding,invoker_pk) — same invoker/outlet/caveats — request_id is the ONLY preimage discriminator; a mis-routed (buggy) or maliciously-routed A-cancel could verify against B's handle if cursors match. Not a NEW capability for a malicious HOST (it already runs B's pump), but wastes the request_id binding; add the assert on the verbatim path. (apply_outlet_cancel_signed path is safe — it builds cancel with self.request_id at 1094.)
- LOW: `apply_outlet_cancel_verbatim` lacks the `pump_exited` guard that `apply_credit_grant` has (dispatch.rs:968). Benign (post-term replay → cursor mismatch CursorAdvanced, or record_cancel no-op on Closed state, no double-settle) but add for parity/clarity.
- Option-B IMPROVES on native path: in-tab invoker signature is self-authenticating → the §5.4.5 CRITICAL#1 caller_did bridge gate (needed only because native bridge wields registry key on caller's behalf) is unnecessary for the forwarded path. Note this in the amendment.
- Q4: cursor-serve response needs MLS-channel authenticity + request_id echo ONLY; node-signing the response would be REDUNDANT (re-checks what the node-side equality cross-check already enforces — negative value per CLAUDE.md redundant-enforcement rule). Attacker (must be MLS member) injecting fake cursor → browser signs wrong seq → node rejects CursorAdvanced → retry → Option-A. Relay drop = availability only → Option-A.
- Provenance BENEFIT justifying the feature vs pure Option-A: invoker's signature on cancel_ack_seq=N is a non-repudiable attestation of the billing boundary; Option-A leaves the boundary as the operator's unsigned credit-stall self-report.
- Anti-underbill works BECAUSE cross-check is EQUALITY not <=: invoker cannot sign a low seq to underpay (mismatch→reject); accepted value is exactly the live cursor.
