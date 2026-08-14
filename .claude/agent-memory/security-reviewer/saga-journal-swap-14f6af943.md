# Saga Journal Durable Swap (14f6af943) — 2026-06-26

File: crates/scp-runtime/src/context/supervisor/saga_journal.rs

## MEDIUM (defense-in-depth gap) — shadow-key canonical check diverges from write path
`load_unresolved` (L559-560) accepts any 20-ASCII-digit suffix as canonical:
`seq_suffix.len()==20 && all(is_ascii_digit)`. But u64::MAX = 18446744073709551615
(20 digits); a planted suffix `99999999999999999999` (20 nines) is >u64::MAX, PASSES
the digit check, sorts lexicographically ABOVE every real `00..` seq, and WINS
latest-per-saga selection → storage-write attacker still overrides FSM state/participants
(resurrect resolved saga / shove live saga to attacker-chosen state). The in-code comment
falsely claims parity with `next_seq_for_saga`, which uses `parse::<u64>()` (REJECTS the
overflow). So the new shadow-key fix closes the `~`/`z`/non-digit class but leaves the
20-digit-overflow class open, and the two paths disagree on "canonical."
Entry carries no signature/MAC — integrity = storage trust + CRC (attacker-recomputable).
This is DiD on an already-trusted backend (encryption-as-access-control), not a primary
bypass — hence MEDIUM. Fix: gate selection on `parse::<u64>().is_ok()` (matching write
path) instead of/in addition to the 20-digit check; ideally also cross-check the decoded
entry's `seq_per_saga` against the key suffix.

## CLEAN
- secret-bearing path genuinely DORMANT: `saga_input_is_secret_bearing` returns false for
  the only live variant (CrossContextToolInvocation); doc honesty verified.
- live `evidence` = CrossContextToolInvocationPrepared (ctx ids, caller DID, tool reg id,
  UCAN proof REFERENCE not bytes, ts, nonce, chain-depth) — coordination metadata, not
  bearer secrets. No secret reaches durable journal.
- `mark_resolved` secret path fails loud on undecodable entry (decode_entry(&bytes)? at
  L685 aborts before terminal marker) — new test correct per §9.4.3.
- `durable_providers_from_handle` (all 4 seams: PyO3/NAPI/UniFFI/scp-node) derives journal+
  mls_storage from ONE Arc<SqliteStorage> ({storage_dir}/mls, SQLCipher, storage_key) by
  construction — same encrypting backend, no unencrypted divergence.
- metric rate-only (no saga_id label), per-saga attribution via SCP-SAGA-RECOVERY log.
  metrics-util is dev-dep (test-only).
- No replay escalation (recovered entry only re-surfaces saga as unresolved; authority via
  existing authenticated commit/abort). Per-instance storage → no cross-instance leakage.
