---
name: project-1877-wasm-share-protocol
description: #1877 directive — WASM reimplements ONLY async/tokio/platform; shares the rest from scp-protocol. Slice 1 verdicts + the membership/sequence drift to watch.
metadata:
  type: project
---

# #1877 — WASM shares scp-protocol (multi-slice)

Owner directive: "WASM should reimplement ONLY what genuinely depends on async/tokio
or platform/JS; share everything else from scp-protocol — even if it means doing away
with recent work." End-state: WASM = thin async/platform shell directly holding shared
scp-protocol sync types.

**Why:** WASM had drifted into bespoke reimplementations of types that are pure-sync and
wasm-safe in scp-protocol (no tokio dependency). The flat role model was accidental
duplication, not a forced divergence.

**How to apply:** When reviewing a #1877 slice, the test is: does the reimplemented thing
*genuinely* need tokio / multi-thread / JS-injected crypto / a platform API? If not, it
should be shared from scp-protocol. "Already built in WASM" is sunk cost — strike it.

## Slice 1 (`refactor(wasm): adopt shared ContextRoleState`) — verdicts

- SOUND: adopt `scp_protocol::context::roles::ContextRoleState` directly (deletes WASM's
  flat `MemberEntry`/`ceiling_strings`/`suspended_capabilities`; fixes a latent bug where
  the old hardcoded role-name match silently accepted undefined/out-of-ceiling roles —
  now `system_assign_role` validates against role_definitions by construction).
- SOUND: keep bespoke `WasmContextExportSnapshot` JSON DTO. NOT a divergence trap —
  spec §23.16.8 "Cross-implementation import (out of scope)" NORMATIVELY mandates
  per-family divergent export formats (native MessagePack v4 vs WASM JSON). Convergence
  on native `ContextSnapshot` would VIOLATE spec. What converges is the *construction*
  (domain sep, full-JCS digest over the family's own snapshot, Ed25519, creator_did
  signer, verify-before-restore), never the bytes. Spec names `wasm_export_snapshot_digest`
  as the reference impl.
- SOUND: string-level import ceiling validation (`validate_imported_ceiling_strings`)
  alongside the typed `ContextRoleState::new` re-validation is NOT anti-grind redundancy:
  `ucan_string_to_capability` is a LOSSY parse that canonicalizes colon-form built-ins,
  erasing the rejected-colon-form distinction; the typed check runs after the parse and
  cannot see it. Delegates to the SHARED grammar `validate_ucan_ceiling_string`.
- SOUND: inline `messages:write` send gate (not a shared `require_capability` chokepoint).
  Native ALSO uses the inline `member_has_capability(MessagesWrite)` pattern at every
  send/deliver site (messaging_helpers.rs:930/1830/2810/...). A chokepoint would DIVERGE
  from native, not converge — reviewer suggestion correctly declined.
- SOUND precedent: WASM directly holds the shared type; the parked `ContextStateMut`
  trait/adapter approach was correctly ABANDONED (trait indirection a model can't track
  = wrong shape, contra agent-first-API tenet). Future slices: "directly hold," not "wrap."

## The drift to watch across slices (medium / coherence)

WASM kept a sidecar `member_sequence_numbers: HashMap<String,u64>` for the MLS counter
instead of adopting the sibling shared type `MembershipState`. Premise "no home in
ContextRoleState" is TRUE but INCOMPLETE: the counter lives in
`scp_protocol::context::membership::MembershipState` → `MemberInfo.sequence_number`
(membership.rs:199-216, with shared `next_sequence_number`/`rollback_sequence_number`).
Native holds BOTH `role_state: ContextRoleState` AND `membership: MembershipState` as
siblings (scp-runtime state.rs:600-602). The sidecar map creates a two-map roster
invariant hand-maintained at every add/remove/import site — the exact drift this program
exists to prevent.

**How to apply:** push the #1877 plan to decide `MembershipState` adoption NOW (program
level), not discover it slice-by-slice. Cheap to reverse in slice 1; expensive once later
slices build on the sidecar map. Links: [[operating-reminders]] cross-slice coherence.
