# recv_sequence floor-guard twin (§23.17.3) — commit e9fe67678

CLEAN review. Added `export_recv_sequence_floors` + `validate_and_merge_recv_sequence_floors`
to crypto/mls/provider.rs, wired into `restore_crypto_state_with_floor_guard`
(context/lifecycle_helpers.rs). Receive-side twin of the epoch floor guard.

Verified sound:
- No DashMap deadlock: Step-1 `contexts.get` guard is a temporary inside `map_or_else`,
  dropped before Step-3 `contexts.get_mut`. `.iter()` in export is on inner HashMap, not DashMap.
- Lexicographic `(u64,u64)` compare correct; regression `import<live`; delta reports epoch
  scalar when epoch regressed else sequence (equal-epoch). Four-case max-merge correct.
- Rollback: on Err, destroy_mls_group (`contexts.remove`) + destroy_sender_key → atomic at
  context level. export called BEFORE destroy. Only bare `restore_crypto_state` prod call is
  inside the guard itself; 4 prod call sites all go through the guard.
- All 4 tests genuine/non-tautological; test #1 (live (5,20) vs stale (3,999)) catches
  epoch-vs-sequence lexicographic confusion.

NON-bugs (informational):
- No overshoot ceiling (epoch twin has MAX_EPOCH_ADVANCE). Spec §23.17.2 Inv 3 = `reject if
  imported<local else max`, NO ceiling required. Epoch ceiling is epoch-poisoning-specific extra.
  Import snapshot is signed by creator_did (trusted verbatim for ceilings/governance) so an
  arbitrarily-high recv floor is spec-sanctioned and strictly weaker than what a malicious
  creator can already do. Not a defect.
- None-mls_state warm respawn: destroy removes entry, no re-insert, floors dropped. Symmetric
  with epoch twin; context ceases to exist so nothing to protect. Not a new defect.

GOTCHA for future me: the agent worktree is at .claude/worktrees/agent-*/. Using the bare
main-repo path /Users/alec/Developer/limn/scp/crates/... reads a STALE (main-branch) copy.
Always prefix reads/greps with the worktree root from env cwd.
