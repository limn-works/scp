# #1909 Phase 2 WASM sender-layer review (commit 6952efad)

Reviewed: WASM encrypt/decrypt header framing, sender_key_epoch, recv_sequence_tracker,
SenderKeyStore swap (HashMap→shared SenderKeyStore), signed replay_state snapshot v5→6.

## Verdict: SOUND. No CRITICAL/HIGH bugs. Two LOW/informational notes.

### Verified correct
- SenderKeyStore swap: every access site (get/set_unchecked/remove/epoch/epochs_for_context/
  restore_epoch_high_water) maps correctly. WASM keys store by RAW context_id; native keys by
  hex(hash). Store is LOCAL-only (never on wire) so the divergence is internally-consistent on
  each side, no interop break.
- decrypt_message ordering: ceiling-reject + replay-reject + missing-key-fail + AEAD-fail all
  return Err BEFORE recv_sequence_tracker.insert (state.rs:276). Tracker advanced ONLY on full
  success. Forged u64::MAX header cannot poison the floor. sender_key .clone()'d so no borrow
  conflict with later insert.
- encrypt_message: same sender_key_epoch feeds AAD and header. Dropped mls_group.epoch() read
  fully removed; manager send passes `seq` only; context_decrypt_message wasm export dropped
  epoch/sequence params; all internal callers updated. No stale TS SDK caller (export not yet
  SDK-wired — pre-existing).
- Snapshot v5→6: replay_state added to signed preimage; #[serde(default)]→None so pre-field
  snapshot round-trips without panic. import parks in pending_replay_state; join_context_encrypted
  .take()s exactly once (consume-once, no double-apply, no leak). Only ONE crypto None→Some
  transition path exists (join_context_encrypted) and it consumes pending.
- governance_rotate_sender_key: saturating_add(1), zeroizes old key. Correct.
- parse_sender_header: length-checked, panic-free on short buffer.
- Tests non-vacuous: header KAT, replay/reorder reject, ceiling-reject-no-advance,
  rotate-advance, snapshot-restore-preserves-replay, tampered-replay-fails-import (mutates
  signed JSON triple, asserts sig error), export/import round-trip.

### LOW-1 (informational): native↔WASM open ordering divergence — NOT a security regression
Native open (provider.rs:1724-1785): lookup key → parse → AEAD decrypt → ceiling → replay → insert.
WASM decrypt_message (state.rs:231-277): parse → ceiling → replay → lookup → AEAD decrypt → insert.
WASM checks ceiling/replay BEFORE AEAD; native AFTER. BOTH only insert tracker after all checks
pass, so the tracker-poisoning defense holds in both. Difference is only the error returned for a
forged-but-undecryptable message in some cases. The cross_family conformance test does NOT exercise
either wrapper's ordering — it calls the shared scp_protocol primitives directly with identical
hardcoded inputs on both "sides", so it proves primitive determinism (trivial) but NOT that the two
wrappers feed matching args/ordering. Genuine convergence (native uses sender_key_epoch+raw ctx_id,
verified at provider.rs:1599/1604/1744) holds, but is asserted by reading code, not by the test.

### LOW-2 (doc only): PerContextState.pending_replay_state doc (manager.rs:500) references
`create_context_encrypted_from_welcome` which does not exist anywhere in the codebase. Only
join_context_encrypted consumes pending_replay_state. Stale doc cross-ref.

### NOTE: stale comment manager.rs:2176 mentions "MLS epoch read" in the send rollback rationale;
that read was removed this commit. Trivial.
