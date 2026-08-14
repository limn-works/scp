---
name: review-2c-saga-dispatch-handshake-phase2d
description: Security review of feat/2c-saga-dispatch (broadcast hosting-handshake types b001f49a6 + Phase 2D replay-before-restore wiring a784ca50d) — CLEAN except one MEDIUM error-code registry/sub-block drift
metadata:
  type: project
---

# feat/2c-saga-dispatch security review (HEAD a784ca50d, worktree saga-2c)

Two commits. Verified: scp-runtime lib 1919 pass / scp-protocol 14 + 26 handshake / crash-recovery startup test pass / pipeline_wiring 63 pass / check-error-codes.sh PASSED.

## Commit b001f49a6 — broadcast hosting_handshake.rs (scp-protocol pure leaf)
CLEAN on all four categories.
- AUTH model sound: request signed by Active Signing Key of `subscriber_did`; grant by broadcast author. `verify()` takes the RESOLVED key as an INPUT param (never trusts the message to name its own key) → signature-valid ≡ "signed by the DID it claims". Signing keys are SEPARATE fn params, never struct fields (no key material in types, no Debug leak).
- §9.5.1 canonical-hash preimage (domain-separated, field-enumerated, length-prefixed VarBytes). Nonce uses `RawBytes(&[u8;16])` — fixed-position fixed-size, no length-prefix ambiguity. `OptVarBytes(ucan)`: present⇒VarBytes(4-BE-len+bytes), absent⇒`CanonicalField::Absent`=SHA-256(0x00) sentinel ≠ zero-len VarBytes(00000000) → gated/ungated never collide (test `ucan_absent_differs_from_present_empty`). verify_strict used.
- Domain seps SCP-BCAST-HOST-REQ-V1: / SCP-BCAST-HOST-GRANT-V1: distinct from each other + envelope/key labels (tested).
- clamp/validate can't be bypassed: sign() calls validate() (rejects expires_at_ms==0) before signing; clamp() is total/infallible folding rate→[1,6000], subs→[1,1_000_000]. Amplification ceilings are TYPE-enforced at sign time.
- Error taxonomy doesn't leak internals (just code + dalek error string).

## Commit a784ca50d — Phase 2D restore_on_startup (replay-before-restore)
CLEAN. No fail-open, journal not attacker-authoritative.
- restore_on_startup (supervisor.rs:7838-area, ~line 7868): `replay_unresolved_sagas().await?;` THEN `restore_all_contexts().await`. `?` short-circuits restore on replay-load failure. Folds both sweeps behind one method so a bridge can't call one without the other / out of order.
- Journal is LOCAL durable recovery HINT, not authorization. recover_committing_entry re-drives idempotent Commit-B (CommitBReserveOutcome::AlreadyCommitted re-emits STORED output, NEVER re-invokes tool) and re-acks A from durable xctx_committed_invocations witness. A tampered/corrupt evidence blob → from_evidence_bytes().ok()==None → conservative NeedsRepair (Committing) or record-keyed local reversal (PreparingB). Journal cannot force an unsafe commit the actors didn't already durably stage.
- ALL 3 prod bridges route through restore_on_startup: PyO3 src/context.rs:4046, napi napi/src/context.rs:3802, UniFFI uniffi/src/bridge.rs:10265, shared common/bridge_instance.rs:1707. WASM wasm/src/context.rs:1248 still calls bare restore_all_contexts — CORRECT (ADR-034 ephemeral, no journal, always errors → no fail-open window).
- pipeline_wiring: restore_on_startup_runs_replay_before_restore (string-pos order pin) + bridge_resume_path_routes_through_restore_on_startup (positive route + NEGATIVE !bare-restore_all_contexts bypass guard). Floor 43→45 additive.

## OBSERVATION (not a finding): bridge_instance.rs:1707-1724 restore_all_persisted_contexts swallows restore_on_startup Err at tracing::debug. A real saga-journal load failure → unresolved sagas stay non-terminal (fail-CLOSED, re-swept next start) but low operator visibility. No unsafe-commit/skip-reversal path. Explicit-visibility callers (the 3 exports) DO surface the error.

## MEDIUM finding — error-code sub-block misassignment + registry omission
hosting_handshake.rs:72/76/84 uses SCP-SAGA-13003/13004/13005. Per .docs/standards/sdk-common.md:60-62, sub-block 13000-13009 is OWNED by scp-protocol cross_context_saga.rs; broadcast-hosting handshake is assigned the RESERVED 13100-13999 band. So the codes (a) encroach on cross_context_saga's sub-block and (b) are absent from the registry table (which enumerates 13000-13002, 13010+). No raw numeric collision (cross_context_saga holds 13000/1/2) so runtime grep-disambiguation still works; check-error-codes.sh only RANGE-checks so it passed. This is artifact-flow/spec-drift on a mechanically-enforced taxonomy: code introduced codes the spec doesn't register, in the wrong owner block. Fix: renumber to 13100/13101/13102 (the reserved handshake band) AND add registry rows.
