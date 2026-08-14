# WASM #1877 slice1 — ContextRoleState verbatim export/import (f319ca863, BLACK-CEIL-01)

Reviewed commit f319ca863 (branch wasm/1877-slice1-adopt-context-role-state). Single file: crates/scp-ffi/wasm/src/manager.rs. consequence.rs NOT touched.

## Verdict: No actionable correctness/concurrency/memory bugs. One LOW doc-comment staleness.

## What was verified sound
- Serde round-trip determinism for embedded `ContextRoleState`: all HashSet fields use `serde_sorted_set`/`serde_sorted_set_map` codecs that sort by each element's RFC 8785 canonical-JSON (serde_util.rs ~line 472-499) — deterministic regardless of iteration order. `CapabilityCeiling.capabilities` and `RoleDefinition.capabilities` BOTH carry the sorted codec. `assignments`/`role_definitions` are HashMaps canonicalized by JCS object-key sorting (serde_json_canonicalizer runs over the whole snapshot on both export 6480 and verify 6612). `RoleAssignment.tokens` is order-preserving Vec. Digest reproducible.
- `member_sequence_numbers` sidecar: every read site uses `.entry(..).or_insert(0)` or `.get(..).copied()` (Option) — NO unwrap/index/panic on a member present in role_state.members but absent in the seq map. Inconsistency is benign (self-heals to 0). Export clones verbatim; import clones verbatim.
- Pre-loop validation: iterates `role_state.members` (DIDs) + `assignments.values()` (role names) + `creator_did` separately. Coverage equivalent to old (members[].did + members[].role). assignments-key-not-in-members would skip DID-validation of that key, but it's signed-verbatim data and just-stored string — no panic. Not a security boundary (envelope signed by creator).
- `validate_entries()` belt at import is redundant-but-harmless (CapabilityCeilingRaw::try_from already runs it at deserialize). CTX_2032 mapping correct.
- No leftover refs to removed fields (creator_did/ceiling_strings/members/suspended_capabilities) except ONE stale comment.
- wasm lib builds clean. `cargo test --target wasm32 --no-run` fails on PRE-EXISTING scp_identity errors in identity.rs (unrelated; scp-identity doesn't link wasm32). Manager unit tests run on HOST target — all 6 changed/new tests PASS.

## LOW finding
- manager.rs:6517 comment says exporter verifying key "resolved from `snapshot.creator_did` on import" — field renamed to `snapshot.role_state.creator_did`. Code at 6523 is correct (`ctx.role_state.creator_did`). Doc-only staleness.

## Regression test non-vacuity PROVEN
- `import_does_not_un_suspend_capability_widened_after_suspension`: genuine. set_ceiling (roles.rs:1687) replaces ONLY self.ceiling, never refreshes member_capabilities. WASM ModifyCeiling dispatch (dispatch_modify_ceiling ~3669) calls set_ceiling ONLY. SuspendAccess arm (4129) calls suspend_all which copies current member_capabilities into suspended set. So post-widen messages:write is in NEITHER set → member_has_capability=false (pre-export). OLD import re-ran system_assign_role vs widened ceiling → member_capabilities regained messages:write while suspended set (from flat field) lacked it → true (RED). New verbatim restore → false (GREEN). Goes through real dispatch_governance_action + real export_context/import_context into fresh manager.
- `snapshot_digest_invariant_under_set_insertion_order` `assert_ne!(raw_forward,raw_reversed)` still holds because helper also sets still-flat Vec fields (read_exclusion_list/revoked_tokens/seen_nonces_v3/executed_proposals/broadcast) sorted only by canonicalize_snapshot_sets, not at serialize time. Not vacuous.

## Pattern note
This change CLOSES a recompute-on-import divergence (WASM re-derived state native restored verbatim) — opposite of the usual "WASM reimplementation drifts from scp-core" pattern. Here convergence-to-native was the fix. Carrying typed shared types verbatim (vs lossy flat projections) is the correct anti-drift move.
