---
name: bcast-hosting-handshake-5-14-13
description: §5.14.13 broadcast hosting-handshake signed types (hosting_handshake.rs) §9.5.1 signing review — CRYPTO-SOUND, no findings (feat/2c-saga-dispatch b001f49a6) + Phase 2D replay-before-restore (a784ca50d)
metadata:
  type: project
---

# Broadcast Hosting Handshake §5.14.13 — CRYPTO-SOUND (no findings)

Branch feat/2c-saga-dispatch, worktree saga-2c. HEAD a784ca50d over b001f49a6 (crypto) over 8a76b7089. 3031 scp-protocol lib tests GREEN incl 26-test hosting_handshake suite.

## File: crates/scp-protocol/src/context/broadcast/hosting_handshake.rs
- BroadcastHostingRequest::sign/verify + BroadcastHostingGrant::sign/verify over §9.5.1 canonical_hash (crypto/canonical.rs). Byte-EXACT match to §5.14.13 normative pseudocode (05-contexts.md:1610-1635).
- REQ preimage SCP-BCAST-HOST-REQ-V1: Fixed32(host_ctx)·Fixed32(bcast_ctx)·VarBytes(subscriber_did)·Fixed32(wrapping_pubkey)·VarBytes(jcs(requested_config))·OptVarBytes(ucan)·RawBytes16(nonce)·U64(timestamp_ms).
- GRANT preimage SCP-BCAST-HOST-GRANT-V1: same first 5 then U64(current_key_epoch)·RawBytes16(nonce)·U64(timestamp_ms). No ucan term.
- (1) SPLICE-RESIST: every var field 4B-BE-len-prefixed (VarBytes). Two adjacent Fixed32 ids schema-fixed-width unambiguous; swap is field-name-visible via named *Fields structs (no positional ctor). byte-exact tests prove order.
- (2) SEPARATORS distinct from each other + SCP-BROADCAST-ENVELOPE-V1: + scp-broadcast-key-v1 (test domain_separators_are_distinct). BOTH registered §9.18.2 (09-security-model.md:1630-1631); cross-checked all 40 registry rows, no collision.
- (3) OptVarBytes(ucan): absent→CanonicalField::Absent→ABSENT_SENTINEL genuine SHA-256(0x00); present→VarBytes(4B len+bytes). present-empty(00000000)≠absent(32B sentinel). test ucan_absent_differs_from_present_empty asserts {absent,empty,"x"} pairwise-distinct. gated≠ungated.
- (4) Ints fixed-width: U64 BE (canonical.rs:113), never IEEE-754. BroadcastHostConfig ints ride jcs(config) via serde_json_canonicalizer (RFC8785 key-sorted, deterministic regardless of struct decl order); all <2^53 lossless; config has NO float/map/Option fields.
- (5) KEY-BIND: verify takes RESOLVED authorized key as required param (subscriber's Active Signing Key for req; bcast author key for grant) — not trusted from msg. verify_strict both paths (rejects malleable/torsion). Signature::from_bytes([u8;64]) infallible dalek v2. tamper-each-field tests incl gated→ungated ucan flip fail. wrong_signer tests fail.
- sign_prehashed_preimage = signing_key.sign(&[u8;32] digest) — byte-identical to cross_context_saga.rs XCTX_RECEIPT_DOMAIN precedent.
- AcceptedHostSnapshotEntry: durable B-side record, gates post-grant HPKE pull (NOT re-presented grant); persists grant-committed wrapping_pubkey (refuses differing key on pull). JCS, no signature preimage.
- No key gen/storage/rotation/destruction in commit; signing keys are caller-supplied &SigningKey kept separate from field structs. No secrets resident → no zeroization concern.

## Phase 2D a784ca50d — recovery-integrity (no new crypto), SOUND
- Supervisor::restore_on_startup (supervisor/supervisor.rs:7838+): replay_unresolved_sagas().await? BEFORE restore_all_contexts().await — matches §17.16.4 (17-persistence:961) ordering proof (non-resident caller→ReversalOutstanding observed by replay before restore makes resident, else misrouted to live-reversal path). Folding both behind one method = can't-call-out-of-order structural defense. ? short-circuits before any restore.
- Journal is node's OWN local durable storage (load_unresolved_sagas, 17:948), NOT attacker wire input → no injected-entry replay/equivocation. Deterministic (FSM-state-keyed), idempotent-by-SagaId. Replayed Commit re-acks durable snapshot + re-serves snapshot-gated pull which RE-APPLIES §5.14.4 gates (block-list + current/unrevoked messages:read UCAN) → no double-delivery, no revocation-bypass on replay (05-contexts.md:1699).

VERDICT: CRYPTO-SOUND, no HIGH/MED/LOW. Read-only review.
