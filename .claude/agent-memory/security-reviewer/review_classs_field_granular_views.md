---
name: review-classs-field-granular-views
description: ADR-049 §9 ClassCMut field-granular view refactor (worktree classs-fin-last) — CLEAN, all 4 invariants intact
metadata:
  type: project
---

# ClassCMut field-granular view refactor — SECURITY-CLEAN

Worktree classs-fin-last (branch classs-fin-last, parent f36b09462). Uncommitted working-tree diff, 13 files. ADR-049 §9 refactor narrowing `state_mut()` callers onto field-granular `ClassCMut` views. Independently verified, ZERO findings.

**Why:** Class-S state (spending-nonce tracker, xctx_caller_reservations, saga_pending, executed_proposals, threshold signers, membership removal, downward-auth ceiling/suspended_caps) must persist FAIL-CLOSED; Class-C best-effort/coalesced.

**How to apply:** If re-reviewing this area, these four invariants hold at this head — re-verify only if the destructures or combinators change.

## Item 1 — no whole-bucket `&mut` to a Class-S-containing struct from any Class-C view (COMPILE-error-by-construction)
- `ClassCMut` (class_s.rs:343): destructures `&mut PerContextState` ONCE in `new` (1310). `class_s` field typed `&'a ClassSState` (line 423, SHARED — `&mut` ergonomic binding coerces to `&` at `Self{}` init). `governance` wrapped in `GovernanceClassCMut` (leaves `governance.class_s` in `..` rest). `membership: &mut MembershipState` is safe ONLY because exposed via `MembershipClassCMut` (no `remove_member`, no whole `&mut`). `role_state: &mut ContextRoleState` is the documented §9 line-194 ACCEPTED Class-C residual (consequence suspend path), exposed safely via `RoleStateClassCMut` for migrated sites (whole `role_state_mut()` slated-for-deletion, do-not-add-callers).
- `GovernanceClassCMut` (495): destructures `&mut GovernanceState`, `class_s: GovernanceClassS` left in `..` — NO ref taken.
- `RoleStateClassCMut` (915): `ceiling`/`suspended_capabilities` bound SHARED `&` (read-only), rest `&mut`.
- `MembershipClassCMut` (1080): holds private `&mut MembershipState`, forwards only structural methods; `remove_subscriber` (broadcast-only, no key secrecy) allowed, general `remove_member` NOT.
- New accessors all checked SAFE: `ClassCMut::from_state`→Self; `ClassCSplit::from_state`→Self (class_s+governance.class_s in `..`, membership shared, role_state the accepted residual); `commit_broadcast_borrows`→Class-C trio; `drain_timed_out_gaps`→Vec (no state ref); `member_dids`→`impl Iterator<&DID>` shared; `member_has_capability`→bool `&self`.
- BACKSTOP: `#![forbid(unsafe_code)]` REAL at scp-runtime/src/lib.rs:21 — the only type-system escape (`*const _ as *mut _`) requires unsafe, forbidden crate-wide.
- The only whole-bucket `&mut PerContextState`/`&mut ClassSState`/`&mut GovernanceClassS` in the file are: `ClassSMut::class_s_mut`/`governance_class_s_mut`/`rest_mut` (the Class-S-CAPABLE view, used ONLY by fail-closed combinators); `ClassSCell::state_mut` (temp dead-code escape hatch, `pub(in crate::context)`); and the `restore_on_failure: FnOnce(&mut ClassSState,S)` closure param of `commit_class_s_keep_restore_split` (a fail-closed combinator). NONE on a Class-C view.

## Item 2 — spending-nonce fail-closed on EVERY send_message/finalize_send terminal (keep-direction)
- `enforce_send_economy` returns `Option<ClassSCommitToken>`, `Some` only on paid (nonce-burning) branch; Err arm issues NO token (consume didn't happen).
- Every abort path in send_message takes `spending_nonce_token.take()` and routes via `discharge_send_abort` (827→`commit_send_nonce_token_on_abort`→`t.commit`), direct `commit_send_nonce_token_on_abort` (payment-auth fail 1198, phase2 fail 1238), direct `t.commit(cell,...)` (no-op lone-member exit 1169), or carries token into `finalize_send` (1303).
- `finalize_send` TTL-expiry early return commits token (2095, `?`-propagates persist err). Main path→`persist_finalized_send` (2170): Some→`t.commit` (2253, on Err rolls seq + returns Err), None→best-effort.
- `t.commit` (class_s.rs:2588): sets `consumed=true` BEFORE persist, persist_state_fail_closed, on Err does NOT roll back Class-S (keep-direction), propagates err. Token is `#[must_use]` + Drop guard (debug_assert+tracing::error) → forgotten commit fails CI loudly.
- `debug_assert_eq!(token.is_some(), deducted_cost.is_some() && spending_ucan.is_some())` (1286) pins token presence to paid gating. No path un-burns the nonce.

## Item 3 — deleted compare_remote_checkpoint_bare / create_checkpoint_if_due replacements preserve §9.9.3/§9.9.4 semantics EXACTLY
- `compare_remote_checkpoint_bare` DELETED; receive path (`deliver_checkpoint_message`, messaging_helpers.rs:1561) now calls view-based `compare_remote_checkpoint(view,...)`. Author-spoof bind (`message.checkpoint.sender_did == envelope sender`, 1549) preserved.
- Both share `classify_remote_checkpoint` core (queries_helpers.rs:877): `verify_remote_checkpoint_authenticity` membership+Ed25519 gate runs FAIL-CLOSED before any compare (890); `ct_eq` constant-time root compare; equal-count+diff-root ⇒ Divergent.
- Dedup: view path inlines `if divergence_is_fresh(...) { emit_equivocation_alert(...) }` — byte-identical to surviving `record_equivocation_if_fresh`. `divergence_is_fresh` (1069): per-sender `(count,root)` HashSet, exact re-presentation suppressed, bounded by MAX_SEQUENTIAL_COMMITS but ALWAYS emits (never silently drops §9.9.4 event). `emit_equivocation_alert` NOT appended to durable Merkle log (receiver-minted ≠ sender-auth).
- `create_checkpoint_if_due`→`create_checkpoint_if_due_view` (threshold `>=50 events` / `>0 && >=600s`, byte-identical) used by send path; `force_create_checkpoint_view`/`_fields` (unconditional) used by close path (lifecycle_helpers:592, handler:524). No swap. Checkpoints Class-C/best-effort by design (`last_seen_remote_checkpoint` = receiver-minted evidence, not replay witness).

## Item 4 — seed_caller_reservation_for_test is test-only, routes fail-closed
- class_s.rs:3000, INSIDE `#[cfg(test)] mod tests` (2700). Routes Class-S insert through `commit_class_s_restore` (the fail-closed combinator, same path prod prepare_a uses). `.expect()` on persist. NOT a production bypass.

## Cross-checks
- NO production `state_mut()` callers outside class_s.rs (messaging migration removed last ones; matches doc claim).
- economy_logic/economy_helpers rollback routes through `ClassCMut::from_state`/`GovernanceClassCMut` (airtight Class-C, cannot reach class_s).
