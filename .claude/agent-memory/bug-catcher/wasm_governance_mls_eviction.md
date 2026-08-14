# WASM governance RemoveMember MLS-eviction review

Branch `fix/wasm-governance-mls-eviction`. Reviewed crypto/group.rs,
crypto/state.rs, manager.rs::dispatch_remove_member, wasm_conformance.rs KAT.

## RE-CONFIRMED CLEAN @ c3f7fe48b (fresh pass 2026-06-23, full review-scope)
HEAD is the docs-clarification commit on top of 66a2c6a5c (self-removal test wording + WASM-backend relay obligation). Re-verified the whole fix fresh: own_did creator/joiner/destroyed-group correctness; both self-removal mechanisms vs native provider.rs:1041/1060 (incl dup-DID tree neither-evicted); fail-closed-keep dispatch ordering; one-sided-commit window (NOT exploitable — parse_proposal_id_bytes pre-validated at propose-time; encode payload is positional-msgpack of 2 Strings, infallible); evicted-cannot-decrypt test soundness (Carol-liveness isolates Bob-failure to epoch advance); no unwrap/expect/index panic in new prod code; hex round-trip; empty-commit paths (no-leaf/broadcast/self). Build wasm32 clean, 379 lib + 3 conformance pass, wasm clippy -D warnings clean. NOTHING ACTIONABLE.

## RESOLVED (HEAD 66a2c6a5c, fresh independent pass 2026-06-23): self-DID short-circuit FIX LANDED — CLEAN.
The HIGH self-removal divergence below (found at b98c5b1a9) is now FIXED at 66a2c6a5c:
- group.rs adds `own_did()` (decodes committer's own-leaf BasicCredential→WasmScpCredential.did; no stored state; correct for creator leaf-0 AND Welcome-joiner non-zero leaf — proven by own_did_returns_joiner_did test).
- `remove_member_by_did`: `if self.own_did()? == member_did { return Ok(Vec::new()) }` BEFORE the scan (native provider.rs:1041 parity — empty no-op, evicts NEITHER leaf even in dup-DID tree).
- `leaf_index_for_did`: ALSO skips own_leaf_index in the scan (native provider.rs:1060, second mechanism). Non-self path unaffected (bob resolves+evicts normally).
- dispatch_remove_member self-removal on encrypted ctx → empty commit but STILL strips members/F5 + appends MemberLeft leaf (manager.rs:9890 drives REAL path — regression guard for old CannotRemoveSelf fail-closed).
- All 32 crypto + 12 manager remove_member + 2 conformance tests PASS; clippy wasm32 clean. own_did uses member.credential by-value, leaf_index_for_did by .clone() — both compile (members() yields owned Member). GroupDestroyed propagated everywhere. No unwrap/expect/index panic in prod paths.
- Remaining LOW (unchanged, honestly disclosed in doc-comments): the 2 wasm_conformance.rs KATs are self-replays (hand-call append_context_event in asserted order); cannot catch a real-path ordering regression. Real-path ordering IS covered by in-crate dispatch tests (manager.rs:9890/9514/9969). Not actionable.
VERDICT at 66a2c6a5c: No actionable defects. The security fix is sound.

---
## (HISTORICAL) HEAD b98c5b1a9 re-review: SELF-REMOVAL DIVERGENCE — HIGH — now FIXED above.
- WASM `leaf_index_for_did` (group.rs) scans ALL members and does NOT skip the own leaf.
  Native `remove_member` (provider.rs:1030) does TWO guards WASM lacks: (1) `if member_did == self.local_did { return Ok(default) }` self-removal no-op (#1294), AND (2) `if member.index == own_index { continue; }` in the scan.
- In WASM the local member's own MLS leaf carries `creator_did` (WasmCryptoState::new_for_context). A RemoveMember proposal targeting the creator's/executor's own DID → leaf_index_for_did finds the OWN leaf → remove_member(&own_index) → OpenMLS `remove_members` → commit_builder `build()` returns `CreateCommitError::CannotRemoveSelf` (openmls-0.8.1 commit_builder.rs:574 `if apply_proposals_values.self_removed && !is_external_commit`) → WasmCryptoError::RemoveMemberFailed → ScpWasmError::Crypto, `?`-propagated.
- RESULT: native returns clean empty-commit no-op + STRIPS membership + appends MemberLeft & GovernanceActionExecuted leaves; WASM ERRORS, member NOT removed, NO leaves appended. Divergent tree::root → false-positive §9.9.3 equivocation, AND governance fails to remove a member native removes. Reachable: NO self-target guard at any layer (dispatch_ceiling_capability None for RemoveMember; no propose-time self-block).
- FIX: in `leaf_index_for_did` or `remove_member_by_did`, skip/short-circuit the own leaf the way native does (need own-leaf-index/local-did accessor on WasmMlsGroup). No WASM test covers self/creator removal.
- LESSON: "mirrors native find_leaf_index_by_did" is NOT enough — native's removal has an EXTRA own-leaf skip + a local_did self-removal short-circuit ABOVE the scan. Always diff the WHOLE native call, not just the named helper.

VERDICT (prior, 97c351df9): erroneously CLEAN. All 367 wasm lib tests + 56 conformance pass
but none exercise self/creator removal.

Verified:
- Borrow: `ctx.crypto.as_mut()` scoped inside `if let` block (NLL); later
  ctx.members/broadcast_context re-borrow OK. Compiler-confirmed.
- Ordering parity with native execute_remove_member (governance_helpers.rs:1231):
  MLS remove FIRST → remove_sender_key → rotate_sender_key → strip membership →
  emit buffer MemberLeft → append durable MemberLeft leaf → wrapper appends
  GovernanceActionExecuted. WASM mirrors exactly.
- MemberLeft leaf: empty payload (native uses EventPayload::default() = empty Vec),
  actor_did = executor (not removed DID), timestamp = convergent proposal.created_at.
  Target DID buffer-only. §9.9.3 parity.
- Fail-closed: only the FIRST crypto step (governance_remove_from_group) is fallible;
  remove_sender_key/rotate_sender_key return () — no half-evicted-still-in-governance
  window. Member stays in ctx.members on Err. (Native needs fail_close_remove_member
  arms because ITS sender-key ops are fallible; WASM's aren't — moot divergence.)
- leaf_index_for_did mirrors native find_leaf_index_by_did: same first-match,
  same silent-skip on credential decode failure (no panic on malformed member).
  WASM returns Ok(None) on miss vs native Err(MemberNotFound) but remove_member_by_did
  normalizes both to RemoveMemberFailed.
- commit hex: hex::encode(&[]) = "" on broadcast/empty path, no panic, round-trippable.
  Surfaced to JS via serialized result JSON (not dead). Cross-member distribution of
  the rotated sender key is a pre-existing, explicitly-documented gap (orthogonal to
  eviction; epoch advance is the lockout).

Test quality:
- evicted_member_cannot_decrypt_after_removal_and_rotation: non-vacuous differential
  (Bob decrypts pre-eviction, fails post; Carol decrypts both). Exercises REAL MLS.
- remove_member_keeps_governance_state_when_mls_eviction_fails: sets REAL crypto
  (single-creator group), forces miss on non-leaf member → Crypto err, asserts member
  kept + no MemberLeft leaf. Real path, non-vacuous.
- remove_member_appends_empty_member_left_leaf_before_executed_wasm: runs on crypto=None
  (empty-commit path) — fine, leaf ordering/payload/ts are crypto-independent.

LOW (non-actionable, noted): the NATIVE-half conformance test
`cross_impl_remove_member_leaf_is_empty_and_precedes_executed` does NOT call
execute_remove_member; it hand-replays the two appends in author-chosen order via the
log provider. So it cannot catch a native ordering regression (would still pass). The
doc-comment honestly explains the runtime test crate can't dep the wasm cdylib, and
native ordering is structurally evident in source. Not a correctness bug; just weaker
coverage than the comment's "drives native's REAL durable appends in order" wording
implies. WASM-side ordering IS driven through the real path.
