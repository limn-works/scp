---
name: project-1877-wasm-sync-convergence
description: #1877 multi-slice program — WASM reimplements ONLY async/tokio/platform, shares everything sync from scp-protocol. Slice-1 precedent + the recurring "rollback on unreachable built-in-role assign" drift to watch for.
metadata:
  type: project
---

# #1877 — WASM sync-convergence program

Directive: WASM bridge reimplements ONLY async/tokio/platform concerns; shares
EVERYTHING sync directly from `scp-protocol`. Each slice deletes a WASM-local
parallel model and holds the shared sync type instead.

**Why:** ADR-034 bars WASM from depending on scp-runtime (tokio multi-thread),
but it CAN depend on scp-protocol (pure sync). Past WASM bridges reimplemented
sync logic locally and drifted from native (e.g. free-form role strings vs
validated `role_definitions`). Convergence kills the drift class.

**Slice 1 (branch wasm/1877-slice1-adopt-context-role-state, HEAD d96c38c0d as of 2026-06-24):**
WASM `PerContextState` now holds shared `scp_protocol::context::roles::ContextRoleState`
instead of `MemberEntry.role` strings + flat `suspended_capabilities` map +
hardcoded role→cap resolver. Judged SOUND (three times now). Fixed latent #1886 (WASM
previously accepted undefined role strings that silently stripped caps).

**F1-REDO (HEAD d96c38c0d) — SOUND.** Extracted `join_context_membership_only`
(membership commit, no event/leaf); unencrypted `join_context` appends leaf+buffer
immediately (native non-MLS join), encrypted `join_context_encrypted` defers BOTH
buffer event + durable leaf until AFTER `join_from_welcome` succeeds. Fixes a REAL
reachable bug: prior code appended the append-only `MemberJoined` leaf BEFORE the
fallible MLS welcome, so a failed welcome left an orphan leaf (can't un-append) +
phantom buffer event = cross-impl event-log divergence. Native-parity claim is
APPROXIMATE not literal: native `join_context` is the ADDER (calls `crypto.add_member`,
Phase 3 MLS → Phase 4 buffer event → Phase 5 leaf); WASM `join_context_encrypted` is
the JOINER (calls `join_from_welcome`). Native has NO joiner-side ContextManager
lifecycle method that updates membership+leaf from a welcome (receive-side append is
DORMANT). Adder path is the right ordering template (MLS-then-leaf, event-before-leaf)
even though the actor differs. Helper extraction is sound structure, not review-shaping.
Two new tests are REAL behavioral (mint real KP + real Welcome), assert leaf-count
invariance on failure + exactly-one on success. 397/397 WASM tests pass, clippy clean.

**Two prior open items NOW RESOLVED:**
- TransferAdmin rollback was ADDED (commit 530752ac5) — restores old admin's prior
  role on promotion failure. The "uniform atomicity" rationale is no longer post-hoc
  inconsistent; comment now honestly says "unreachable by construction... exists for
  uniform fail-closed atomicity... if a future change made promotion fallible."
- `join_context_membership_only` comment now correctly distinguishes dead-by-construction
  built-in-role rollback from the load-bearing `dispatch_add_member` (caller-supplied role)
  one. The comment-accuracy fix my memory prescribed landed.

**ModifyCeiling-converge (HEAD eb276450e) — SOUND, with one PROGRAM-LEVEL shared defect surfaced (not a slice-1 blocker).** WASM `dispatch_modify_ceiling` dropped `set_ceiling_and_refresh` (now `#[cfg(test)]`-only scaffolding) and now does validate(§5.3.1.1) → `role_state.set_ceiling` → done. The removed eager refresh was a REAL reachable security bug on a governed WIDEN: `suspend_all` snapshots a member's `member_capabilities` into the suspended set; refresh recomputed `member_capabilities` to include the newly-added cap; `prune_suspensions_to_role_grants` is SHRINK-only (retain ∩, never adds), so the suspended set never gained the new cap → suspended member silently regained it. Removal fixes this; regression test `test_wasm_suspended_member_stays_suspended_across_ceiling_widen` is real behavioral. Convergence verified against native `apply_pending_ceiling_modification` (governance_helpers.rs:401).
  - PARITY NUANCE (minor, worth a comment fix not a blocker): native applies via DIRECT FIELD WRITE `state.role_state.ceiling = CapabilityCeiling::new(...)` — it does NOT call the validated `set_ceiling` chokepoint. WASM calls `set_ceiling` (validated). WASM is STRICTLY SAFER (defense-in-depth, entries also pre-validated). Native relies on proposal-time validation only. The comment "WASM matches that exactly" overclaims by one notch (native field-write vs WASM validated-mutator) — same stored result, slightly different safety posture. Not a defect in WASM.
  - SHARED DEFECT (model.rs:member_capabilities is a role-assignment-time SNAPSHOT, never recomputed against live ceiling; recomputed only on next system_assign_role): on a ceiling NARROW, a member's member_capabilities still contains caps now OUTSIDE the new ceiling, and member_has_capability returns true for them until the next reassignment = LAZY NARROW-REVOCATION. This is identical in native and WASM (both stale-on-ceiling-change). The commit trades the WIDEN un-suspension bug (FIXED) for INHERITING native's pre-existing narrow-staleness — but that staleness was ALREADY in native and is arguably what the DEFERRED two-phase work (CeilingModificationPending notification window + re-derive at apply) must close. Converging to native here is the RIGHT call (a WASM-local refresh that diverges from native is worse than a shared, documented, deferred gap). The narrow-staleness is a PROGRAM-LEVEL ADR question, NOT a slice-1 regression — slice 1 did not introduce it and correctly does not paper over it WASM-side-only.

**Timestamp-source open question (PROGRAM-LEVEL, not this slice):** WASM samples
`now_secs()` fresh at leaf append (post-MLS); native captures once at Phase 1. Both are
committer-appended-only + NOT replicated (dormant), so "whose clock stamps the convergent
leaf" is a forward ADR-051 step, not a slice-1 defect. Slice correctly preserves local semantics.

**BLACK-CEIL-01 export/import verbatim-restore (HEAD f319ca863) — SOUND, Option B correct.**
WASM snapshot now carries typed `ContextRoleState` + restores VERBATIM (native parity
at lifecycle_helpers.rs:2074 `role_state: export.snapshot.role_state`); deleted the flat
projection + the recompute-on-import (`system_assign_role` per member) that re-granted a
suspended-then-widened member the widened cap. 401/401 WASM tests pass, wasm clippy clean.
Regression test `import_does_not_un_suspend_capability_widened_after_suspension` is real
behavioral (governed suspend → widen → round-trip into FRESH manager → assert no regain).
- Option B beats Option A on merit: A (keep flat + add member_capabilities) would re-mint
  tokens via system_assign_role → token-vs-caps skew, a SECOND divergence. B converges.
- Verbatim-trust is SOUND: envelope binds exporter_did==creator_did + verify_strict Ed25519
  (key resolved from creator_did NOT envelope; empty sig rejected). Creator is the trust root
  for their own context — a creator crafting a self-serving snapshot is not a threat (they own
  it). Signature authenticates ORIGIN; well-formedness covered by validate_entries.
- Deleted `validate_imported_ceiling_strings` was the BLACK-005 string-launder guard (ran
  BEFORE the lossy `ucan_string_to_capability` parse that canonicalized colon-form built-ins).
  Deleting it is SOUND: ceiling now serializes as typed `Capability` enums (derive Serialize),
  NOT UCAN strings — there is no string-parse-and-launder step on import anymore, so BLACK-005
  is structurally impossible on this path. The class of attack the check guarded no longer exists.
- Remaining `validate_entries()` belt is NOT redundant-weaker-recheck of the typed deserialize:
  it's NATIVE PARITY (native runs the same belt) and is the explicit greppable §5.3.1.1 fail-loud.
  The `CapabilityCeilingRaw` try_from already rejects malformed at deserialize; the belt is a
  cheap one-liner mirror of native, not an ever-growing denylist. Keep it. (Could arguably go
  since try_from is sound-by-construction, but parity > marginal dedup here; not a finding.)
- canonicalize_snapshot_sets dropping ceiling/members/suspended sorts is SOUND: those fields now
  live in role_state whose set fields use serde_sorted_set/_map codecs (content-sorted at
  serialize) + maps JCS-canonicalized by key; inner sets are pub(crate) so a sort here is
  impossible anyway. Subtree is byte-stable without the dropped sorts.

**THE ONE REAL FINDING (QUESTION, not blocker): member_sequence_numbers sidecar is a
mis-framed boundary = half-migration smell.** The slice comment claims the per-member MLS
sequence counter has "no home in the shared ContextRoleState" — literally true but WRONG FRAME.
The shared home is `scp_protocol::context::membership::MembershipState` (membership.rs:129):
`members: HashMap<DID, MemberInfo>`, `MemberInfo.sequence_number: u64` (membership.rs:107-116),
with `next_sequence_number`/`rollback_sequence_number`. Native's ContextSnapshot carries
`membership: MembershipState` (state.rs:601 "members, roles, sequence numbers") and import
restores it VERBATIM at lifecycle_helpers.rs:2072 — the EXACT parallel to role_state:2074. WASM
uses MembershipState NOWHERE (grep = 0 hits). So #1877's "share all sync from scp-protocol" has
ANOTHER unconverged shared type sitting right next to the one this slice converged. Converging
ONLY ContextRoleState and leaving MembershipState as a flat HashMap<String,u64> sidecar is a
half-migration — the SAME drift class #1877 exists to kill, one type over. NOT a slice-1
regression (predates it; the sidecar already existed flat), and the slice did not make it worse.
But the comment's "no shared home" framing risks HARDENING the sidecar as a permanent decision
when it's actually the next slice's convergence target. Recommendation: accept this slice
(role-state convergence is correct + the security fix is real), but DOWNGRADE the comment from
"no home in the shared ContextRoleState" (true-but-misleading) to "MembershipState convergence is
deferred to a later #1877 slice" so it's logged as a known remaining migration, not a settled
boundary. This is the right incremental slice boundary IF that follow-up is tracked.

**Cross-impl import is ALREADY not byte-parity (pre-existing, not this slice):** WASM and native
SHARE the signing domain `SCP-CONTEXT-EXPORT-V1:` + digest construction
(SHA-256(domain || scope_tag || JCS(snapshot))) — a strong signal cross-impl import is an intended
invariant — BUT the two snapshot DTOs are structurally different (native ContextSnapshot has
merkle_root + ContextParams + MembershipState; WASM has params_json:Value + member_sequence_numbers
+ ~15 serde(default) fields + own digest). WASM comment line ~7497 concedes "NOT byte-parity with
native ContextSnapshot." So native-export→WASM-import (and reverse) is ALREADY broken on shape, not
by this slice. This is a PROGRAM-LEVEL #1877 question (does WASM export need full ContextSnapshot
byte-parity, or is it WASM-local-only round-trip?) that the directive should answer explicitly —
the shared domain separator implies parity is wanted but the format makes it impossible. Flag to
Alec as the real endpoint question for #1877, separate from slice-1 go/no-go.

**The right convergence precedent (apply to every remaining slice):**
1. Hold the shared sync type directly (delete the local parallel model, don't extend it).
2. Re-apply BOUNDARY validation at the bridge (e.g. positive
   `member_has_capability(MessagesWrite)` send-gate).
3. Keep ONLY genuinely-platform state local (e.g. `member_sequence_numbers` MLS
   sidecar — deferred to a later slice to fold into shared MembershipState; deferral
   is correct, it's a distinct type-migration with its own export/import parity surface).

**How to apply / drift to watch for:** iterative review on slice 1 added rollbacks
to join/subscribe membership-add paths "mirroring dispatch_add_member." VERIFY the
premise per-path before accepting such symmetry:
- `ContextRoleState::system_assign_role` (roles.rs:1731) fails only 3 ways:
  MemberNotInContext / RoleNotFound / CapabilityOutsideCeiling.
- Built-in roles (member/admin/subscriber/...) are constructed by FILTERING caps
  through `ceiling.contains()` (roles.rs builtin_*), so a built-in assign is
  infallible-by-construction (member just inserted + role always defined + caps ⊆ ceiling).
- Therefore: rollback on a HARDCODED built-in role assign (join="member",
  subscribe="subscriber", TransferAdmin "admin"/"member") guards a DEAD error =
  defensive symmetry, not load-bearing.
- Rollback on a CALLER-SUPPLIED role (AddMember{role}) IS load-bearing (RoleNotFound
  reachable; tested). Don't let reviewers conflate the two — the comment
  "uniform atomicity across all membership-add paths" overclaims; TransferAdmin has
  NO rollback despite a worse partial-state (admin vacancy), proving the rationale
  is post-hoc. Fix is comment accuracy, not code. Not a blocker.

**REFINEMENT (final-slice pass 2026-06-24):** the load-bearing rollback is load-bearing
for FRESH adds but UNSAFE on RE-ADDS. `dispatch_add_member` (~L3886) is the ONLY
membership-add path lacking a preceding `members.contains` guard (join@1841 rejects
already-joined; subscribe@5524 wraps in `if !contains`; encrypted-join@2362 is a fresh
joiner). `AddMember{existing_member, bad_role}` is reachable (no upstream already-member
guard, both bridges treat AddMember as idempotent re-role upsert) → WASM `members.remove`
EVICTS a legitimately-present member + orphans their assignments/member_capabilities
(partial rollback). Native does NOT roll back (coalesce-window-acceptable) → member stays.
Test only covers the fresh newcomer. Fix options: (a) guard `dispatch_add_member` with
`if !contains` like the others (idempotent re-role, no eviction), or (b) escalate whether
AddMember-on-existing should reject at validate-time. See
[[wasm-native-convergence-1877]]. This is a real divergence the slice INTRODUCED — not a
comment nit.
