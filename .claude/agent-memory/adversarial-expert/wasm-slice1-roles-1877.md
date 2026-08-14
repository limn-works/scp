---
name: wasm-slice1-roles-1877
description: PR #1905 #1877 slice 1 — WASM bridge adopts shared ContextRoleState; SHIP verdict + why the #1891 bug class is closed by construction
metadata:
  type: project
---

# PR #1905 — WASM ContextRoleState adoption (#1877 slice 1)

Verdict: **SHIP** (single ship/no-ship gate, HEAD 0d4acd537). Could not break it after genuine effort.

**Why:** The WASM bridge's flat per-context role reimpl (MemberEntry struct, ceiling_strings, flat STRING suspended_capabilities, hardcoded role resolver, creator_did) is fully replaced by `scp_protocol::context::roles::ContextRoleState`. 4 files, +3699/-1212. 418 wasm lib tests + 120 protocol roles tests + 32 consequence tests + pipeline_wiring all green. clippy clean (wasm32 lib CI form + host --all-targets).

## #1891 bug class eliminated by construction — VERIFIED end-to-end
- Suspension storage AND the send/publish/governance gates both operate on the TYPED `Capability` enum (enum equality), never display strings.
- Only string boundary = `ucan_string_to_capability` (manager.rs:224) → `Capability::new`, which canonically resolves BOTH spellings of every built-in (colon form + UCAN wire form: `bridging`/`bridging:*`→Bridging, `tool:invoke:*`/`tool_invoke:*`→ToolInvokeAll, `context:child:create`/`context_child:create`→ChildContextCreate). No `_`-bearing custom collides (kebab-only custom grammar §5.3.1.1).
- consequence apply_suspend uses `suspend_capabilities_typed` (NO string round-trip). Gate `member_has_capability(&Capability::MessagesWrite)` typed. Divergent-display class structurally impossible.
- 3 ported #1891 regression tests are NON-VACUOUS and exercise ENFORCEMENT not storage: `apply_suspend_enforces_capabilities_with_divergent_display_form` asserts member_has_capability flips true→false for Bridging+ToolInvokeAll; `governance_suspend_restore_uses_canonical_form_for_all_shapes` covers Custom("bridging") masquerade + Custom("custom:foo"); exhaustive 18-builtin conversion parity test.

## Membership split-brain — all paths sound
- `dispatch_add_member` conditional rollback (manager.rs:3935-3957): new member+bad role → fully removed; EXISTING member re-add+bad role → left intact. `system_assign_role` (roles.rs:1799) validates member-in-ctx/role-exists/ceiling BEFORE any mutation (step 4), so failure never corrupts assignments/member_capabilities. No "gone-from-members-but-retains-caps" window.
- encrypted-join rollback (manager.rs:2384-2398): on MLS welcome failure strips members/assignments/member_capabilities/suspensions/seq; leaf deferred to post-success → no orphan leaf, no phantom member.
- `dispatch_remove_member`: MLS eviction FIRST (hard boundary, `?` keeps member present on crypto failure), governance strip only after success. WASM clears suspensions on removal (safer than native, which leaks them — documented divergence, native should converge TO WASM).

## TransferAdmin — no zero-admin, creator_did immutable
- manager.rs:4129: rejects non-member new_admin before mutation; demotes ALL current admins to member, then promotes new_admin to admin (ends with exactly one admin even if new_admin was already admin). creator_did NEVER touched (immutable UCAN root / export signer).

## Export/import — forgery/tamper/non-creator all rejected
- Import order (deserialize_and_verify_envelope, manager.rs:6609): size bound → version gate (rejects unsigned pre-format) → exporter_did==creator_did → Ed25519 verify_strict over JCS-canonicalized snapshot, key resolved from snapshot.creator_did (NOT envelope) → HMAC defense-in-depth.
- Malformed-ceiling-past-deserialize CLOSED: snapshot embeds typed `ContextRoleState` → `CapabilityCeiling` `#[serde(try_from=CapabilityCeilingRaw)]` validating deserialize fires at from_slice BEFORE sig check. Redundant grammar belt at import:6900.
- BLACK-CEIL-01 closed: role_state restored VERBATIM (no member_capabilities recompute) → suspended-then-widened member stays suspended across round-trip.

## pipeline_wiring re-point — LEGITIMATE, strictly stronger
- `wasm_join_context_inspects_spending_ucan_and_economic_policy` re-pointed from `join_context` to `join_context_membership_only`. Gate genuinely centralized there; BOTH join_context (manager:1901) and join_context_encrypted (manager:2348) call it. All 3 assertions retained (spending_ucan_jwt, economic_policy, SCP-ECON-12096). NOT a weakening — now covers both paths via one chokepoint.

## No half-merged artifacts
- MemberEntry struct: 0 defs in authoritative HEAD (git show HEAD:). The on-disk Read showed a STALE copy — this worktree's Read tool serves stale manager.rs (mtime races during regen). ALWAYS verify via `git show HEAD:`. All ceiling_strings/build_ceiling_strings/MemberEntry refs in HEAD are doc-comment history only.

## Non-blocking observations (deferred, documented, native-side or interim)
- Per-author sequence off-by-one (WASM post-inc base 0 vs native pre-inc base 1) — out of ADR-050 byte-parity scope, must converge on MembershipState adoption.
- Native leaves suspended_capabilities on remove (latent native bug); WASM clears (safer). Convergence deferred to shared-removal slice.
- Per-action EventType leaves (AdminTransferred/CeilingModified) not emitted on WASM — §9.9.3 leaf-count divergence, tracked by ignored conformance test.
