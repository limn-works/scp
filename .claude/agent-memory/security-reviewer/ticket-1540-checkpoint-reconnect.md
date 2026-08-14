---
name: ticket-1540-checkpoint-reconnect
description: Security review of #1540 checkpoint exchange + equivocation detection on receive path + FFI reconnect driver
metadata:
  type: project
---

# #1540 Checkpoint Exchange + Equivocation Sync + Reconnect Driver (2026-06-14) — APPROVE

Branch feat/1540-checkpoint-equivocation-sync. Reviewed full diff (33 files).

## Receive path (messaging_helpers.rs deliver_checkpoint_message)
- CLEAN. Checkpoint dispatch at line 1084 happens AFTER full MLS decrypt + sender-DID binding
  (1040-1053) + access-key unwrap via verify_and_unwrap (1064-1077). Does NOT bypass access key
  like Recovery does (sender_is_admin only set for Recovery msg type).
- CHECKPOINT_PAYLOAD_TAG (\0-prefixed) + deny_unknown_fields on CheckpointMessage AND
  ConsistencyCheckpoint. Author-binding: message.checkpoint.sender_did MUST == MLS envelope sender.
- compare_remote_checkpoint (queries_helpers.rs:724) order is correct: membership(731) →
  key resolve(739) → Ed25519 sig verify(745) → THEN Merkle root compare(771). Sig before roots = matches §23.7 checklist.
- Returns Ok(None) — never advances content sequence. Confirmed.
- DoS: plaintext bounded by inner-envelope 256KB bucket + MAX_ENVELOPE_SIZE before rmp_serde.
  verify_checkpoint_signature uses try_into() (Err not panic) on non-64-byte sig (checkpoint.rs:752).

## Reconnect driver (scp-ffi/common/src/reconnect.rs)
- CLEAN. Relay data fully untrusted: all blobs fed via deliver_commit_blob → DeliverIncoming
  (full MLS auth). Errors logged+continue (debug), not fatal. Bounded loop: .take(limit) where
  limit=policy.max_sequential_commits=100 (SyncPolicy::default, not wire-controlled).
- envelope_to_buffered recomputes blob_id = SHA-256(envelope); stored_at=local now (relay ts not trusted).
- saturating_sub(5) safe. Welcome path (subscribe_and_await_welcome) feeds relay blobs to actor
  which authenticates — let _ = ignore is safe.

## Actor commands
- New: LocalMlsEpoch, NeedsReconnect (queries), BuildLocalCheckpoint, CompareRemoteCheckpoint
  (messaging), ClearNeedsReconnect, IssueMlsUpdate (lifecycle). All route via mailbox.
- IssueMlsUpdate: broadcast-context guard; advance_epoch is authoritative ratchet; mirrors
  mls_epoch+=1 (advisory, for tier decisions — not a crypto-state divergence vuln).
- No authorization gap: reconnect only drives caller's OWN contexts (member's own DID + own signing key).

## Leakage / §9.9.4 no-silent-discard
- CLEAN. EquivocationDetected surfaced on all 4 bridges (PyO3 escapes each field; NAPI/UniFFI
  escape whole formatted string; both non-lossy, HTML-escaped, DID escaped). No secret exposure.
- Signing key: resolve_signing_key (pre-existing helper) → SigningKeyBytes (zeroizing) → in-process
  only, never crosses FFI outward. SDK wrappers surface only flat report counts.

## Enforcement honesty
- pipeline_wiring.rs STRENGTHENED (replaced weak contains("checkpoint") OR-clause with real
  call-site fn_body_contains assertions). Capability matrix adds reconnect w/ honest WASM exemption.
