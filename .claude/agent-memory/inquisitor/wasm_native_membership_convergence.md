---
name: wasm-native-membership-convergence
description: Two unspecified native↔WASM semantic divergences surviving the #1877 ContextRoleState slice, rooted in the shared type lacking a member-removal primitive; decide + spec before the deferred MembershipState slice.
metadata:
  type: project
---

#1877 native↔WASM convergence — slice 1 adopted shared `ContextRoleState` in the WASM
bridge (`crates/scp-ffi/wasm/src/manager.rs`) and deferred `MembershipState` (kept
`member_sequence_numbers` as a named sidecar). The slice is SOUND/coherent (root-cause
fixes, no sunk-cost; export byte-parity correctly NOT claimed per ADR-050 §29/§37). Two
genuine semantic divergences survive — both in the deferred sequence/membership domain,
both ungrounded in any spec:

1. **Per-member sequence off-by-one.** WASM records the PRE-increment value (first
   message seq=0; `manager.rs:2089-2093`, `:5611-5615`). Native
   `MembershipState::next_sequence_number` returns the POST-increment value (first
   message seq=1; `membership.rs:198`, asserted `context_lifecycle.rs:304`). Bound into
   sender-layer AAD via `encrypt_message(... sequence)` but does NOT break decryption
   (receiver is handed the sequence, not recompute). Pre-existing on origin/main, carried
   verbatim. NOTE: both sides use plain `+= 1` — the divergence is read-before vs
   read-after increment, NOT saturating_add vs += (that framing was stale).

2. **Suspension state on member removal.** Native `execute_remove_member`
   (`lifecycle_helpers.rs:327-336`) strips members/assignments/member_capabilities but
   LEAVES `suspended_capabilities` dangling. WASM removal paths (`manager.rs:1962`,
   `:2356`, `:4005`) CLEAR suspensions via `restore_capabilities`. On remove-then-rejoin
   native re-denies old suspended caps; WASM starts clean. Runs OPPOSITE to the slice's
   "match native" goal in the very domain the slice otherwise hardened.

**Why:** Root cause is `ContextRoleState` (`roles.rs:1372`) exposing add/assign/suspend
but NO member-removal primitive — every removal path (native too) hand-strips separate
public fields at ~5 WASM sites; the sidecar lengthens the checklist.

**How to apply:** When the deferred `MembershipState` slice comes up: (a) make both
divergences named acceptance criteria; (b) add `ContextRoleState::remove_member` with a
DECIDED suspension policy (suspension-survives-removal yes/no) so removal is one call;
(c) decide canonical sequence base (0 vs 1) and spec it in §9 sequence semantics. Escalate
(a)/(b)/(c) as program-level decisions so the follow-up converges to a grounded target.

**TransferAdmin slice (HEAD d05e8ad7d) — SOUND.** WASM TransferAdmin converged to native
`execute_transfer_admin`: reject non-member before mutation (CTX-2015), demote EVERY admin
holder to "member", promote new_admin, NEVER touch creator_did. Coherent:
- creator_did = immutable UCAN-root/export-signer/HMAC/operator_did/exporter_did; admin = a
  transferable ROLE. After transfer the export signer is a demoted non-admin member (could
  even leave) — FINE: export verification resolves the creator's key from their DID doc,
  not from context role. This decoupling lives in the SHARED scp-protocol `ContextRoleState`,
  so it's a protocol-level decision, not WASM-local.
- "Demote ALL admins" loop is defensive: spec (phase-6.md:2568) makes TransferAdmin
  **SingleAdmin-model ONLY**, so exactly one admin exists. Not importing a questionable
  multi-admin design. Transfer-to-self is a benign net no-op (no vacancy).
- Tests exercise the production dispatch_governance_action path (happy + non-member reject).
The slice as a unit is a coherent convergence step; the only live divergence is item 2
above (suspended-on-remove), correctly deferred to the shared remove_member helper rather
than ad-hoc patched (patching native now = a second hand-written convergence #1877 exists
to delete). Go-recommend with item 2 ESCALATED as a human decision, not a blocker.
