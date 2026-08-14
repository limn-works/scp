---
name: broadcast-ban-evasion-self-leave
description: Broadcast read-ban can be self-laundered via leave_context clearing read_exclusion_list; defeats the subscribe admission gate fix
metadata:
  type: project
---

# BLACK: Broadcast ban evasion via self-leave (defeats read_exclusion_list subscribe gate)

Context: A fix added a `read_exclusion_list` admission gate in
`crates/scp-runtime/src/context/broadcast_helpers.rs:97` (`subscribe_broadcast`)
so a governance-banned broadcast subscriber cannot replay a still-valid
`messages:read` UCAN to re-appear on the roster. Capability-matrix note claims
"a banned subscriber cannot replay a still-valid grant to re-appear on the roster."

**The invariant is FALSE.** Ban-laundering chain:

1. `execute_revoke` (governance_helpers.rs:915-935) read-scope ban: inserts DID
   into `access.read_exclusion_list`, calls `bc.governance_ban_subscriber`
   (removes from broadcast `subscribers` roster + block_lists all authors +
   rotates keys), suspends MessagesRead. **Never removes from `state.membership`**
   (verified — no `membership.remove_member` in execute_revoke). So banned M
   stays a member.
2. M self-leaves: `LeaveContext { caller_did: M, member_did: M }` — exposed on
   all 4 FFI bridges (PyO3 context.rs:3108, NAPI context.rs:1607, UniFFI
   bridge.rs:10203). `leave_context` (lifecycle_helpers.rs) self-leave path
   (caller==member) needs NO capability. It runs:
   - `role_state.remove_member(M)` → clears M's MessagesRead suspension
   - `read_exclusion_list.remove(M)` (lifecycle_helpers.rs:342) → **CLEARS THE BAN**
   - removes M from membership
3. M re-subscribes with the SAME still-valid grant → gate at :97 now sees
   `read_exclusion_list.contains(M) == false` → passes; UCAN passes full pipeline
   (creator-signed root token, audience=M, in ceiling, not CID-revoked, valid).
   M re-added to roster + membership + MemberJoined event-log leaf.

Root cause: `read_exclusion_list` is overloaded — both a governance-ban record
(authority decision, must be durable/unclearable-by-subject) AND a leftover
CEK-exclusion cleared on clean leave (lifecycle_helpers.rs:342 clears it
unconditionally on self-leave). Self-leave lets the banned party unilaterally
undo the governance decision.

**Residual mitigation (limits but does not eliminate):** author `block_list`
entries are NOT cleared by unsubscribe (broadcast/mod.rs:768-813) or leave, so
M stays on EXISTING authors' block_lists → `handle_key_request`
(broadcast/mod.rs:1906) still denies keys from existing authors. BUT: M gains a
roster entry (violates the exact stated invariant), restores MessagesRead
capability, and receives keys from ANY author who joins/registers AFTER the
re-subscribe (not on the stale block_list). So: full ban-record evasion +
future-content confidentiality bypass.

Fix options: (a) leave/remove must NOT clear read_exclusion_list for a
governance-banned DID (distinguish ban vs leftover), or (b) ban must also remove
from membership so self-leave finds nothing, or (c) subscribe gate should also
consult a separate durable ban record that self-leave can't touch.

Negative results confirmed clean under the delta:
- Empty InMemoryProofResolver change is a SECURITY IMPROVEMENT: root tokens
  (prf=[]) skip resolver (validate.rs:1113); delegated tokens fail closed
  (DelegationChainBroken). Removes xctx_ucan_proofs cross-contamination surface.
- DID comparison exact-string everywhere; casing/whitespace evasion blocked by
  UCAN audience binding + canonical DID encoding (extract_public_key_from_did).
- `BroadcastContext::register_subscriber` (protocol) is test-only (no runtime callers).
- Both subscribe gate (:97) and serve gate (:765) read identical
  `cell.access.read_exclusion_list`; ban writes same field. No drift.
