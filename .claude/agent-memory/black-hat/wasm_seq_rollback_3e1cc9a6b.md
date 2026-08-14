---
name: wasm-seq-rollback-3e1cc9a6b
description: WASM send-path per-sender sequence rollback (commit 3e1cc9a6b) — adversarial sweep found NO break; rollback is exploit-resistant
metadata:
  type: project
---

# WASM send-path sequence rollback — final sweep (commit 3e1cc9a6b)

Target: `crates/scp-ffi/wasm/src/manager.rs` `send_message` (line ~2011) +
`publish_broadcast` (~5618). Commit made `send_message` roll back the reserved
per-sender MLS sequence on encrypt-path failure (base64 / MLS epoch / encrypt)
via `saturating_sub(1)`, removing a fresh `0` entry created purely to reserve a
now-failed send.

**Verdict: COULD NOT BREAK after genuine effort.** 10 adversarial probes built +
RUN through real production dispatch with real MLS crypto. All defend correctly.
Mutation-verified non-vacuous: disabling rollback turned all 6 send probes RED
(e.g. accepted seqs `[0,2,3,5]` instead of `[0,1,2,3]` — gaps from burned seqs).

## Why it holds
- On `&mut self` (single-threaded WASM) no reentrancy/TOCTOU between lock phases.
  The native confused-deputy/context-recreation attacks DO NOT apply to this
  synchronous bridge — exclusive borrow for the whole call. Structural defense.
- Rollback is exact: success strictly advances (+1), failure restores to floor,
  fresh-entry-on-failed-first-send is removed (pre-send shape restored).
- `seq_was_present==false` branch only reachable in prod via a creator-signed
  import with members ⊋ seq-keys (import restores `member_sequence_numbers`
  VERBATIM at manager.rs ~6912 with NO cross-consistency check vs role_state.members).
  Creator authority = out of scope; creator could do anything anyway. Path is
  defensively correct regardless (proven by probe ATTACK 3).
- `publish_broadcast` correctly needs NO rollback: increment (~5683) is followed
  only by infallible `push_event`. Both publish entry points
  (`publish_broadcast_asset`, `publish_broadcast_assets`) validate path/mime/
  deploy_id/body/serialization BEFORE calling publish, so a failed asset never
  reserves a seq. Batch is non-atomic but every consumed seq maps to a real
  recorded event (the convergence invariant).

## Severity downgrade on AEAD concern
Sequence is bound into AAD ONLY, NOT the AES-GCM nonce. Nonce is random per
invocation (`OsRng.fill_bytes`, `scp-protocol/src/crypto/sender_keys/encrypt.rs`
line 58-59). So sequence reuse does NOT cause nonce reuse / key recovery. The
rollback prevents per-author ORDERING/dedup desync (honest members deriving
different gapless streams), not an AEAD catastrophe. Still HIGH-worthy as a
convergence bug, but not the nonce-reuse CRITICAL.

## Capability/governance probes (also clean)
- Suspended member CANNOT propose governance (suspension-aware member_has_capability).
- TransferAdmin to non-member rejected pre-mutation; original admin retained.
- Self-TransferAdmin leaves EXACTLY ONE admin (no zero-admin). creator_did never
  touched by role transfer (in-band creator authority = out of scope).
- send/publish both gate on positive `messages:write` member_has_capability
  (suspension-aware single check) before reserving any sequence.
