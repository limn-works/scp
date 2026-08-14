---
name: wasm-1877-slice1-context-role-state-c65552c9e
description: #1877 convergence slice 1 — WASM PerContextState adopts shared scp-protocol ContextRoleState (deletes flat role/ceiling/suspension reimpl); ALIGNED, 1 pre-existing send-auth gap noted out-of-scope
metadata:
  type: project
---

# #1877 slice 1: WASM adopts shared ContextRoleState @ c65552c9e (branch wasm/1877-slice1-adopt-context-role-state) — ALIGNED, ship

Directive: "WASM reimplements ONLY async/tokio/platform-dependent things; share everything sync." First convergence slice. Diff: consequence.rs (+65/-/) + manager.rs (+733/-557), 2 files only.

**What it does (verified by reading shared roles.rs + native governance_helpers.rs):**
- Deletes WASM `MemberEntry`, flat `members: HashMap<String,MemberEntry>`, `ceiling_strings: HashSet<String>`, `suspended_capabilities: HashMap<String,HashSet<String>>`, `creator_did` fields. Replaces with `role_state: scp_protocol::context::roles::ContextRoleState` (the SAME type native holds) + `member_sequence_numbers: HashMap<String,u64>` (MLS encryption state — correctly kept WASM-local; no home in ContextRoleState).
- `member_has_capability` now delegates to `ContextRoleState::member_has_capability` (suspension-first then member_capabilities set) via `ucan_string_to_capability` parser.
- All governance arms (ChangeRole→new `dispatch_change_role`, AddMember, RemoveMember, TransferAdmin, ResetMember, Suspend/Restore, subscribe) route through `system_assign_role` / `suspend_capabilities` / `suspend_all` / `restore_capabilities`.

**#1886 fix BY CONSTRUCTION (native-matching, CONFIRMED):** native execute_change_role(gov_helpers:1124) + execute_add_member(:941) both route roles::system_assign_role → RoleNotFound for undefined role. WASM old flat model silently accepted any free-form role string (member then lost all caps). New WASM uses same system_assign_role → undefined/out-of-ceiling role REJECTED. 3 new tests prove it (change_role_to_undefined_rejected, change_role_to_defined_succeeds, add_member_undefined_rejected). AddMember rolls back the members.insert on assignment failure (fail-closed atomicity). ALIGNED.

**suspend_all convergence:** old WASM SuspendAccess suspended the whole CEILING; new uses ContextRoleState::suspend_all = copies member's effective member_capabilities (role-granted set) into suspended. Native uses the SAME suspend_all. So this CONVERGES WASM→native and is spec-correct. (Whole-ceiling was the WASM divergence being closed.)

**Pre-existing send-auth gap (OUT OF SCOPE for this slice — correctly so):** native send_message (messaging_helpers.rs:689) gates on POSITIVE member_has_capability(MessagesWrite) then distinguishes suspension only for the error msg. WASM send (manager.rs:1861-1879) checks ONLY suspension + membership — NO positive write-grant check. So a WASM `observer` (no messages:write) can send. VERIFIED this gap is UNCHANGED by the slice (old code also only checked suspended_capabilities.contains("messages:write")). It is a pre-existing WASM divergence; this slice merely makes it *fixable* (positive grant set now exists via role_state). Alignment verdict: fixing it is a SEPARATE concern — this slice is state-representation only; adding the gate is an authorization-behavior change that belongs in a follow-up (or the #206/governed-ceiling slice). NOT a blocker for THIS slice, but it should be tracked and fixed — it is a real fail-to-revoke-direction hole.

**Deferrals confirmed legitimate (documented, pre-existing tracked gaps):** RoleAssigned leaf (#206) + native two-phase governed-ceiling deferral. The ignored conformance test `wasm_native_full_governance_eventtype_parity_pending` explicitly lists RoleAssigned among ~40 not-yet-appended WASM events. ModifyCeiling stays single-phase immediate (set_ceiling_and_refresh) with a comment naming the two-phase deferral as a separate slice. Coherent — no half-wired dispatch.

**Export snapshot wire format UNCHANGED (correct for this slice):** export/import re-materialize the flat WasmExportMember list + suspended map FROM role_state (translation layer); signed snapshot bytes identical. Keeping bespoke snapshot format is acceptable — converging it is a later concern, not implied by the state-rep directive.

**Byte-equality verified:** default_ceiling() = same 10 caps as old build_ceiling_strings(empty); to_ucan_string_set() uses ucan_capability_name() → "tool_invoke:*"/"context:close" matching old hardcoded strings.

**ADR-034 respected:** only adds imports FROM scp-protocol (already wasm-safe); no scp-runtime dep. wasm32 check clean. 382 wasm lib tests pass + 57 conformance pass (1 ignored = the #206 deferral).

**Artifact flow:** code conforms to shared type; no spec/ADR edits (none needed — shared type is upstream). Correct direction.

LESSON: a "delete reimpl, adopt shared sync type" convergence slice can EXPOSE (make visible/fixable) a pre-existing behavioral gap on the diverged side without INTRODUCING it. Check whether the gap predates the diff (git/old-code) before classifying: if unchanged → out-of-scope for a state-rep slice but track it; only a NEW gap is a blocker. Classify the gap by direction: this one is fail-to-REVOKE (observer can write) = real hole, vs fail-to-grant = safe.
