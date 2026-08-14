---
name: pr1540-equivocation-sync
description: Crypto review of #1540 checkpoint-equivocation reconnection sync — APPROVE w/ one LOW gap
metadata:
  type: project
---

# PR #1540 — Checkpoint Equivocation Reconnection Sync (reviewed 2026-06-14)

Branch `feat/1540-checkpoint-equivocation-sync`. APPROVE, one LOW follow-up.

**Why:** §9.9.3 equivocation detection tier (a) + ADR-029 reconnection driver. Adds forensic-root persistence, replay idempotency, ct_eq root compare, zeroized FFI signing key.

**How to apply:** load-bearing facts for any future work on `compare_remote_checkpoint` / `record_equivocation_if_fresh` / reconnect driver.

## Sound
- `verify_remote_checkpoint_authenticity` (queries_helpers.rs:719) runs FIRST in compare_remote_checkpoint (:766): membership then verify_checkpoint_signature, fail-closed `?`. So persisted remote_merkle_root + timestamp are signature-covered member-signed values (compute_checkpoint_canonical_hash covers all 6 fields incl merkle_root+timestamp, checkpoint.rs:760).
- checkpoint.rs canonical hash UNCHANGED (only added serde derives + deny_unknown_fields + serde_bytes on sig). Domain sep SCP-CHECKPOINT-V1: + length-prefixed var fields intact.
- ct_eq: queries_helpers.rs:794 bool::from(local_root.ct_eq(&remote.merkle_root)), both [u8;32], subtle declared in scp-runtime Cargo.toml:61. Correct.
- Zeroize: all 3 relay-client bridges (PyO3 context.rs:179, NAPI napi/context.rs:167, UniFFI bridge.rs:202) = export SigningKey -> Zeroizing::new(sk.to_bytes()) -> by-value into reconnect_contexts_no_drain. Driver holds Zeroizing<[u8;32]> (reconnect.rs:70,90), reconstructs SigningKey per-call at :376 (ed25519_dalek 2.x ZeroizeOnDrop). Reports carry NO key material. WASM correctly omitted (ADR-034, no driver).
- Freshness: state.rs:948 HashMap<DID,(u64,u64)> keyed per-sender. timestamp is sig-covered so relay can't forge it; gate runs post-verify so relay can only replay exact tuple (suppressed). Malicious signer backdate only suppresses ITS OWN later self-equivocations (self-defeating; first already recorded). Higher event_count always fresh (lexicographic tuple > + is_none_or).

## LOW gap (non-blocking follow-up)
- record_equivocation_if_fresh (queries_helpers.rs:856) freshness key = (event_count, timestamp), does NOT include merkle_root. Two DISTINCT divergent checkpoints from same sender at same (count,timestamp) but different roots -> 2nd root's forensic evidence dropped (§9.9.4 says security events MUST NOT be discarded). Exploitability VERY LOW: 1st detection appends EquivocationDetected -> local count advances -> later compare = Behind/Ahead not Divergent -> never reaches gate (test note reconnect_sync.rs:484). Window = 2nd forgery before 1st append commits.
- FIX: add remote.merkle_root to freshness key (or per-sender set of seen roots). Also doc comment queries_helpers.rs:847 overclaims "once per distinct divergent checkpoint" — actually once per (count,timestamp). Fix key OR comment.
