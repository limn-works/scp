# slice1-roles WASM role-state convergence — black-hat probe results

Target: `crates/scp-ffi/wasm/src/manager.rs` adopting shared `ContextRoleState`.
HEAD probed: 4babda7ba. All probes RUN as Rust tests in throwaway worktree.

## ONE REAL FINDING — MEDIUM (robustness/convergence divergence)
### BLACK-SEQ-01: raw `*seq_entry += 1` diverges from native `saturating_add`
- WASM `send_message` (manager.rs:2093) and `publish_broadcast` (manager.rs:5615)
  do `*seq_entry += 1` on `member_sequence_numbers`.
- Native deliberately uses `saturating_add` (actor/sequence.rs:134, messaging_helpers.rs:3033/3144)
  and `checked_add` (mls/provider.rs:1621) — comment: "fails loudly rather than wrapping silently".
- Debug/test build: PANIC ("attempt to add with overflow") = DoS. PROBE A confirmed.
- Release build (wasm-pack --release, overflow-checks OFF): WRAPS u64::MAX -> 0 silently
  = MLS/per-author sequence-number REUSE / sender-key replay surface. PROBE A2 confirmed (seq->0).
- Reachability: seq lives in member_sequence_numbers, which IS covered by the Ed25519
  snapshot signature (PROBE F: tamper rejected SCP-CTX-2093). So NOT network-reachable by an
  unprivileged relay/peer. Realistic actor = malicious/buggy CREATOR exporting to importing peers,
  OR pure robustness gap. Fix: mirror native — use saturating_add in both WASM send paths.

## Probes that FOUND NOTHING (defenses hold — clean results)
- PROBE C: observer (read-only role) send_message rejected (SCP-PERM-3000). OK.
- PROBE G: ModifyCeiling WIDEN does NOT escalate an observer (no per-member refresh, native-parity). OK.
- PROBE H (BLACK-CEIL-01): SuspendAccess -> ceiling widen -> export -> import keeps member
  suspended (verbatim role_state restore); send rejected post-import. OK.
- PROBE E: member in role_state but missing from member_sequence_numbers -> or_insert(0), no panic. OK.
- PROBE F: member_sequence_numbers tamper in signed bytes -> import rejected (signed). OK.
- Export/import envelope: bounded input, exact version gate (==5), exporter==creator binding,
  key resolved from creator_did (never envelope), verify_strict over JCS digest. Solid.

## NOT a WASM finding (native-equivalent, per task scope)
- PROBE D: SuspendAccess -> ChangeRole(observer) -> ChangeRole(member) RE-GRANTS messages:write.
  This is shared-core `prune_suspensions_to_role_grants` SHRINK-only semantics (roles.rs:1640) —
  documented + identical on native. Suspension is dropped when the intermediate role lacks the cap.
  Protocol observation only: a "ban" that survives a demote is lost if the member transits a role
  that does not grant the banned cap. Same on all bridges; flag to protocol owners, not a WASM bug.
